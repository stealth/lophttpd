/*
 * Copyright (C) 2008-2011 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <unistd.h>
#include <fcntl.h>
#include <cassert>
#include <cerrno>
#include <string>
#include <cstring>
#include <ctime>
#include <ctype.h>
#include <iostream>
#include <csignal>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "lonely.h"
#include "misc.h"
#include "socket.h"
#ifdef linux
#include <sys/sendfile.h>
#else
#include <sys/uio.h>
#endif

using namespace std;
using namespace NS_Socket;


struct ext2CT {
	const std::string extension, c_type;
} content_types[] = {
	{".apk", "application/octet-stream"},
	{".bmp", "image/bmp"},
	{".c", "text/plain"},
	{".cc", "text/plain"},
	{".gif", "image/gif"},
	{".gz", "application/gzip"},
	{".h", "text/plain"},
	{".htm", "text/html"},
	{".html", "text/html"},
	{".jpg", "image/jpg"},
	{".js", "application/x-javascript"},
	{".pdf", "application/pdf"},
	{".png", "image/png"},
	{".ps", "application/postscript"},
	{".tar", "application/x-tar"},
	{".tgz", "application/gzip"},
	{".txt", "text/plain"},
	{".xml", "text/xml"},
	{".zip", "application/zip"},
	{"", ""}
};


// Must match order of http_error_code_t enum
string http_error_msgs[] = {
	"400 Bad Request",
	"401 Unauthorized",
	"404 Not Found",
	"405 Method Not Allowed",
	"406 Not Acceptable",
	"411 Length Required",
	"414 Request-URI Too Large",
	"500 Internal Server Error",
	"501 Not Implemented",
	"503 Service Unavailable"
};


const char *lonely::why()
{
	return err.c_str();
}

int lonely::init(u_int16_t local_port)
{
	cur_time = time(NULL);

	int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		err = "lonely::init::socket:";
		err += strerror(errno);
		return -1;
	}

	// bind & listen
	if (bind_local(sock_fd, local_port, 1, 1) < 0) {
		err = NS_Socket::why();
		return -1;
	}

	// allocate poll array
	struct rlimit rl;
	rl.rlim_cur = (1<<16)+1;
	rl.rlim_max = rl.rlim_cur;

	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
			err = "lonely::init::getrlimit:";
			err += strerror(errno);
			return -1;
		}
	}

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	pfds = new (nothrow) pollfd[rl.rlim_cur];
	if (!pfds) {
		err = "loneley::init::OOM";
		return -1;
	}
	memset(pfds, 0, sizeof(struct pollfd)*rl.rlim_cur);
	for (unsigned int i = 0; i < rl.rlim_cur; ++i)
		pfds[i].fd = -1;

	// setup listening socket for polling
	max_fd = sock_fd;
	first_fd = sock_fd;
	pfds[sock_fd].fd = sock_fd;
	pfds[sock_fd].events = POLLIN|POLLOUT;

	fd2state[sock_fd] = new struct status;
	fd2state[sock_fd]->state = STATE_ACCEPTING;
	fd2state[sock_fd]->keep_alive = 1;


	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	return 0;
}


void lonely::cleanup(int fd)
{
//	assert(pfds[fd].fd == fd);
	pfds[fd].fd = -1;
	pfds[fd].events = 0;
	close(fd);

	if (fd2state.find(fd) != fd2state.end() && fd2state[fd]) {
		delete fd2state[fd];
		fd2state[fd] = NULL;
	}
	if (max_fd == fd)
		--max_fd;
}


void lonely::calc_max_fd()
{
	for (int i = max_fd; i >= first_fd; --i) {
		if (pfds[i].fd != -1) {
			max_fd = i;
			return;
		}
	}
}


int lonely::loop()
{
	int i = 0;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	struct tm tm;
	struct timeval tv;

	for (;;) {
		// 0 means timeout which we also need to handle
		if (poll(pfds, max_fd + 1, 30*1000) < 0)
			continue;

		memset(&tv, 0, sizeof(tv));
		memset(&tm, 0, sizeof(tm));
		gettimeofday(&tv, NULL);
		cur_time = tv.tv_sec;
		localtime_r(&cur_time, &tm);
		strftime(local_date, sizeof(local_date), "%a, %d %b %Y %H:%M:%S GMT%z", &tm);
		gmtime_r(&cur_time, &tm);
		strftime(gmt_date, sizeof(gmt_date), "%a, %d %b %Y %H:%M:%S GMT", &tm);

		for (i = first_fd; i <= max_fd; ++i) {
			if (pfds[i].fd == -1)
				continue;
			if (fd2state.find(i) == fd2state.end() || !fd2state[i]) {
				cleanup(i);
				continue;
			}

			// more than 30s no data?! Don't time out accept socket.
			if (fd2state[i]->state != STATE_ACCEPTING &&
			    cur_time - fd2state[i]->alive_time > timeout_alive) {
				if (pfds[i].revents == 0) {
					cleanup(i);
					continue;
				}
			}

			if (pfds[i].revents == 0)
				continue;
			cur_peer = i;
			fd2state[i]->alive_time = cur_time;

			// new connection ready to accept?
			if (fd2state[i]->state == STATE_ACCEPTING) {
				pfds[i].revents = 0;
				pfds[i].events = POLLIN|POLLOUT;
				int afd = accept(pfds[i].fd, (struct sockaddr *)&sin, &slen);
				if (afd < 0) {
					if (errno == EMFILE || errno == ENFILE)
						clear_cache();
					continue;
				}
				pfds[afd].fd = afd;
				pfds[afd].events = POLLIN;
				pfds[afd].revents = 0;

				int flags = fcntl(afd, F_GETFL);
				fcntl(afd, F_SETFL, flags|O_NONBLOCK);

				fd2state[afd] = new (nothrow) struct status;
				if (!fd2state[afd]) {
					cleanup(afd);
					continue;
				}
				memset(fd2state[afd], 0, sizeof(struct status));
				fd2state[afd]->state = STATE_CONNECTED;
				fd2state[afd]->alive_time = cur_time;
				fd2state[afd]->sin = sin;

				if (afd > max_fd)
					max_fd = afd;
			} else if (fd2state[i]->state == STATE_CONNECTED) {
				if (handle_request() < 0) {
					cleanup(i);
					continue;
				}
			} else if (fd2state[i]->state == STATE_TRANSFERING) {
				transfer();
			}

			// do not glue together the above and below if()'s because
			// transfer() may change state so we need a 2nd if

			// In case of TRANSFERING we have data to send, so POLLOUT.
			if (fd2state[i]->state == STATE_TRANSFERING) {
				pfds[i].events = POLLOUT;
			} else if (fd2state[i]->state == STATE_CONNECTED)
				pfds[i].events = POLLIN;

			if (!fd2state[i]->keep_alive && fd2state[i]->state == STATE_CONNECTED)
				cleanup(i);
		}
		calc_max_fd();
	}
	return 0;
}


// In which timeframe complete header must arrive after 1st byte received
const uint8_t lonely_http::timeout_header = 3;

// In which timeframe a new request must arrive after connect/transfer
const uint8_t lonely::timeout_alive = 30;


int lonely_http::open_log(const string &logfile, const string &method, int core = 0)
{
	logger = new (nothrow) log_provider;
	if (!logger) {
		err = "OOM";
		return -1;
	}
	int r = logger->open_log(logfile, method, core);
	if (r < 0)
		err = logger->why();
	return r;
}


int lonely_http::put_http_header()
{
	string http_header = "HTTP/1.1 200 OK\r\n"
	                     "Server: lophttpd\r\n"
	                     "Date: ";
	http_header += gmt_date;
	http_header += "\r\nContent-Type: %s\r\n"
	               "Content-Length: %zu\r\n\r\n";

	char h_buf[http_header.size() + 128];
	string c_type = "application/data";
	int i = 0;

	for (i = 0; !content_types[i].extension.empty(); ++i) {
		if (cur_path.size() <= content_types[i].extension.size())
			continue;
		if (strcasestr(cur_path.c_str() + cur_path.size() - content_types[i].extension.size(),
		               content_types[i].extension.c_str()))
			break;
	}
	if (!content_types[i].c_type.empty())
		c_type = content_types[i].c_type;
	snprintf(h_buf, sizeof(h_buf), http_header.c_str(), c_type.c_str(), cur_stat.st_size);
	writen(cur_peer, h_buf, strlen(h_buf));
	return 0;
}


int lonely_http::send_genindex()
{
	string http_header = "HTTP/1.1 200 OK\r\n"
	                     "Server: lophttpd\r\n"
	                     "Date: ";
	http_header += gmt_date;
	http_header += "\r\nContent-Length: %zu\r\n"
                       "Content-Type: text/html\r\n\r\n%s";

	size_t l = http_header.size() + 128 + NS_Misc::dir2index[cur_path].size();
	char *h_buf = new (nothrow) char[l];
	if (!h_buf)
		return 0;
	snprintf(h_buf, l, http_header.c_str(), NS_Misc::dir2index[cur_path].size(),
	         NS_Misc::dir2index[cur_path].c_str());
	int r = writen(cur_peer, h_buf, strlen(h_buf));
	delete [] h_buf;
	return r;
}


int lonely_http::transfer()
{
	struct peer_file pf;

	if (peer2file.find(cur_peer) == peer2file.end()) {
		if ((pf.fd = open(cur_path)) < 0) {
			err = "lonely_http::transfer::open:";
			err += strerror(errno);
			return -1;
		}

		// stat() already happened in GET/POST

		pf.offset = 0;
		pf.size = cur_stat.st_size;
		pf.path = cur_path;

		put_http_header();

	} else {
		pf = peer2file[cur_peer];
	}

#ifdef linux
	ssize_t r = sendfile(cur_peer, pf.fd, &pf.offset, pf.size);
#else
// FreeBSD tested at least
	off_t sbytes = 0;
	ssize_t r = sendfile(pf.fd, cur_peer, pf.offset, 0, NULL, &sbytes, 0);
	if (sbytes > 0)
		pf.offset += sbytes;
#endif

	// Dummy reset of r, if EAGAIN appears on nonblocking socket
	if (errno == EAGAIN)
		r = 1;

#ifdef linux
	if (r <= 0) {
#else
// On FreeBSD, 0 retval means success
	if (r < 0) {
#endif
		// Error? Kick client and erase from cache
		peer2file.erase(cur_peer);
		fd2state[cur_peer]->state = STATE_CONNECTED;
		fd2state[cur_peer]->keep_alive = 0;
		if (r < 0) {
			close(pf.fd);
			file2fd.erase(pf.path);
		}
	} else if (pf.offset == (ssize_t)pf.size) {
		peer2file.erase(cur_peer);
		//close(pf.fd); Do not close, due to caching
		fd2state[cur_peer]->state = STATE_CONNECTED;
		fd2state[cur_peer]->header_time  = 0;
	} else {
		peer2file[cur_peer] = pf;
		fd2state[cur_peer]->state = STATE_TRANSFERING;
	}

	return 0;
}


void lonely_http::log(const string &msg)
{
	if (!logger)
		return;

	string prefix = local_date;

	char dst[128];
	inet_ntop(AF_INET, &fd2state[cur_peer]->sin.sin_addr, dst, sizeof(dst));
	prefix += ": ";
	prefix += dst;
	prefix += ": ";
	prefix += msg;
	logger->log(prefix);
}


int lonely_http::HEAD()
{
	string head = "HTTP/1.1 200 OK\r\nDate: ";
	head += gmt_date;
	head += "\r\nServer: lophttpd\r\n\r\n";
	fd2state[cur_peer]->keep_alive = 0;

	string logstr = "HEAD\n";
	log(logstr);
	return writen(cur_peer, head.c_str(), head.size());
}


int lonely_http::OPTIONS()
{
	string reply = "HTTP/1.1 200 OK\r\nDate: ";
	reply += gmt_date;
	reply += "\r\nServer: lophttpd\r\nContent-Length: 0\r\nAllow: OPTIONS, GET, HEAD, POST\r\n\r\n";
	log("OPTIONS");
	return writen(cur_peer, reply.c_str(), reply.size());
}


int lonely_http::DELETE()
{
	log("DELETE");
	return send_error(HTTP_ERROR_405);
}


int lonely_http::CONNECT()
{
	log("CONNECT");
	return send_error(HTTP_ERROR_405);
}


int lonely_http::TRACE()
{
	log("TRACE");
	return send_error(HTTP_ERROR_501);
}


int lonely_http::PUT()
{
	log("PUT");
	return send_error(HTTP_ERROR_405);
}



int lonely_http::POST()
{
	return GET();
}


// for sighandler if new files appear in webroot
void lonely_http::clear_cache()
{
	map<int, int> dont_close;
	file2stat.clear();

	// dont close files inbetween transfer
	for (map<int, struct peer_file>::iterator i = peer2file.begin(); i != peer2file.end(); ++i)
		dont_close[i->second.fd] = 1;

	for (map<string, int>::iterator i = file2fd.begin(); i != file2fd.end(); ++i) {
		if (dont_close.find(i->second) == dont_close.end()) {
			close(i->second);
			file2fd.erase(i);
		}
	}
}


int lonely_http::stat(const string &path)
{
	int r = 0;
	memset(&cur_stat, 0, sizeof(cur_stat));

	if (file2stat.find(path) != file2stat.end()) {
		cur_stat = file2stat[path];
	} else {
		r = ::stat(path.c_str(), &cur_stat);
		// do not cache failures
		if (r == 0)
			file2stat[path] = cur_stat;
	}

	return r;
}


int lonely_http::open(const string &path)
{
	int fd = -1;

	if (file2fd.find(path) != file2fd.end()) {
		fd = file2fd[path];
	} else {
		fd = ::open(path.c_str(), O_RDONLY);
		if (fd >= 0) {
			file2fd[path] = fd;
		// Too many open files? Drop caches
		} else if (errno == EMFILE || errno == ENFILE) {
			clear_cache();
			fd = ::open(path.c_str(), O_RDONLY);
			if (fd >= 0)
				file2fd[path] = fd;
		}
	}
	return fd;
}


int lonely_http::de_escape_path()
{
	if (cur_path.find("%") == string::npos)
		return 0;
	string tmp;
	tmp.resize(16);
	size_t pos = 0;
	unsigned char c = 0, c1, c2;
	tmp = "";
	while ((pos = cur_path.find("%")) != string::npos) {
		// must have at least 2 chars after % escape
		if (pos > cur_path.size() - 3)
			return -1;
		if (!isxdigit(cur_path[pos + 1]) || !isxdigit(cur_path[pos + 2]))
			return -1;
		c1 = toupper(cur_path[pos + 1]);
		c2 = toupper(cur_path[pos + 2]);
		if (c1 >= 'A' && c1 <= 'F')
			c = (10 + c1 - 'A')<<4;
		else
			c = (c1 - '0')<<4;
		if (c2 >= 'A' && c2 <= 'F')
			c += (10 + c2 - 'A');
		else
			c += (c2 - '0');
		tmp.push_back(c);
		cur_path.replace(pos, 3, tmp, 0, 1);
		tmp = "";
	}
	return 0;
}


int lonely_http::GET()
{
	string logstr = "GET ";
	logstr += cur_path;
	logstr += "\n";
	log(logstr);

	if (de_escape_path() < 0)
		return send_error(HTTP_ERROR_400);

	int r = 0;

	if ((r = stat(cur_path)) == 0 && (S_ISREG(cur_stat.st_mode))) {
		if (transfer() < 0)
			send_error(HTTP_ERROR_404);
	} else if (r == 0 && S_ISDIR(cur_stat.st_mode)) {
		string o_path = cur_path;
		// index.html exists? send!
		cur_path += "/index.html";
		if (stat(cur_path) == 0 && (S_ISREG(cur_stat.st_mode))) {
			if (transfer() < 0)
				send_error(HTTP_ERROR_404);
		} else {
			cur_path = o_path;
			if (send_genindex() < 0)
				return -1;
		}
	} else {
		send_error(HTTP_ERROR_404);
		return -1;
	}

	return 0;
}


int lonely_http::send_error(http_error_code_t e)
{
	string http_header = "HTTP/1.1 ";


	if (e >= HTTP_ERROR_END)
		e = HTTP_ERROR_400;
	http_header += http_error_msgs[e];
	http_header += "\r\nServer: lophttpd\r\nDate: ";
	http_header += gmt_date;
	http_header += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	writen(cur_peer, http_header.c_str(), http_header.size());
	fd2state[cur_peer]->keep_alive = 0;
	return 0;
}


int lonely_http::handle_request()
{
	char req_buf[2048], *ptr = NULL, *ptr2 = NULL, *end_ptr = NULL, *last_byte = &req_buf[sizeof(req_buf) - 1],
	     body[2048];
	int n;

	memset(req_buf, 0, sizeof(req_buf));

	// peek to find hopefully a complete header
	if ((n = recv(cur_peer, req_buf, sizeof(req_buf) - 1, MSG_PEEK)) <= 0) {
		err = "lonely_http::handle_connection::recv:";
		err += strerror(errno);
		return -1;
	}

	// If first read, set initial timestamp for header TO
	if (fd2state[cur_peer]->header_time == 0)
		fd2state[cur_peer]->header_time = cur_time;

	// incomplete header?
	if ((ptr = strstr(req_buf, "\r\n\r\n")) == NULL) {
		if (cur_time - fd2state[cur_peer]->header_time > timeout_header) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		fd2state[cur_peer]->keep_alive = 1;
		return 0;
	}

	// read exactly the header from the queue, including \r\n\r\n
	if ((n = read(cur_peer, req_buf, ptr - req_buf + 4)) <= 0) {
		err = "lonely_http::handle_connection::read:";
		err += strerror(errno);
		return -1;
	}

	end_ptr = ptr + n;

	// For POST requests, we also require a Content-Length that matches.
	// The above if() already ensured we have header until "\r\n\r\n"
	if (strncmp(req_buf, "POST", 4) == 0) {
		if ((ptr = strcasestr(req_buf, "Content-Length:")) != NULL) {
			while (ptr < end_ptr) {
				if (*ptr == ' ')
					++ptr;
			}
			if (ptr >= end_ptr) {
				send_error(HTTP_ERROR_400);
				return -1;
			}
			size_t cl = strtoul(ptr, NULL, 10);
			if (cl >= sizeof(body))
				send_error(HTTP_ERROR_414);
			// The body should be right here, we dont mind if stupid senders
			// send them separately
			if ((size_t)recv(cur_peer, body, sizeof(body), MSG_DONTWAIT) != cl) {
				send_error(HTTP_ERROR_400);
				return -1;
			}
		} else {
			send_error(HTTP_ERROR_411);
			return -1;
		}
	}


	fd2state[cur_peer]->keep_alive = 0;
	int (lonely_http::*action)() = NULL;

	if (strncasecmp(req_buf, "OPTIONS", 7) == 0)
		action = &lonely_http::OPTIONS;
	else if (strncasecmp(req_buf, "GET", 3) == 0)
		action = &lonely_http::GET;
	else if (strncasecmp(req_buf, "POST", 4) == 0)
		action = &lonely_http::POST;
	else if (strncasecmp(req_buf, "HEAD", 4) == 0)
		action = &lonely_http::HEAD;
	else if (strncasecmp(req_buf, "PUT", 3) == 0)
		action = &lonely_http::PUT;
	else if (strncasecmp(req_buf, "DELETE", 6) == 0)
		action = &lonely_http::DELETE;
	else if (strncasecmp(req_buf, "TRACE", 5) == 0)
		action = &lonely_http::TRACE;
	else {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	ptr = strchr(req_buf, '/');
	if (!ptr) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	end_ptr = ptr + strcspn(ptr + 1, "? \t\r");

	if (end_ptr >= last_byte) {
		send_error(HTTP_ERROR_400);
		return -1;
	}
	end_ptr[1] = 0;

	cur_path = ptr;

	ptr = end_ptr + 2; // rest of header
	if (ptr > last_byte) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	if ((ptr2 = strcasestr(ptr, "Connection:")) && cur_peer < 30000) {
		ptr2 += 11;
		for (;ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}
		if (ptr2 >= last_byte) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		if (strncasecmp(ptr2, "keep-alive", 10) == 0) {
			fd2state[cur_peer]->keep_alive = 1;
		}
	}
	if (vhosts && (ptr2 = strcasestr(ptr, "Host:"))) {
		ptr2 += 5;
		for (; ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}

		if (ptr2 >= last_byte) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		if ((end_ptr = strcasestr(ptr2, "\r\n"))) {

			*end_ptr = 0;

			// Not a security issue, but makes no sense
			if (string(ptr2) == "icons") {
				send_error(HTTP_ERROR_404);
				return -1;
			}
			// If already requesting vhost files (genindex), then, do not prepend
			// vhost path again
			if (!strstr(cur_path.c_str(), "vhost")) {
				string tmps = cur_path;
				cur_path = "/vhost";
				cur_path += ptr2;
				if (tmps != "/")
					cur_path += tmps;
			}
		} else {
			send_error(HTTP_ERROR_400);
			return -1;
		}

	}

	return (this->*action)();
}

