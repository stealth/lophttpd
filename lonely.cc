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
#include <netinet/tcp.h>
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
	// This one must be at index 0 and 1, as we keep a cache of
	// file <-> content-type with and index to this table
	{".data", "application/data"},
	{".html", "text/html"},

	{".apk", "application/octet-stream"},
	{".avi", "video/x-msvideo"},
	{".bmp", "image/bmp"},
	{".bib", "text/x-bibtex"},
	{".c", "text/x-csrc"},
	{".cc", "text/x-c++src"},
	{".cpp", "text/x-c++src"},
	{".cxx", "text/x-c++src"},
	{".C", "text/x-c++src"},
	{".dtd", "text/x-dtd"},
	{".dvi", "application/x-dvi"},
	{".fig", "image/x-xfig"},
	{".flv", "application/flash-video"},
	{".gif", "image/gif"},
	{".gz", "application/gzip"},
	{".h", "text/x-chdr"},
	{".hh", "text/x-chdr"},
	{".htm", "text/html"},
	{".ico", "image/x-ico"},
	{".iso", "application/x-cd-image"},
	{".java", "text/x-java"},
	{".jpg", "image/jpg"},
	{".js", "application/x-javascript"},
	{".mp3", "audio/mpeg"},
	{".mpeg", "video/mpeg"},
	{".mpg", "video/mpeg"},
	{".ogg", "application/ogg"},
	{".pdf", "application/pdf"},
	{".pls", "audio/x-scpls"},
	{".png", "image/png"},
	{".ps", "application/postscript"},
	{".ps.gz", "application/x-gzpostscript"},
	{".rar", "application/x-rar-compressed"},
	{".rdf", "text/rdf"},
	{".rss", "text/rss"},
	{".sgm", "text/sgml"},
	{".sgml", "text/sgml"},
	{".svg", "image/svg+xml"},
	{".tar", "application/x-tar"},
	{".tar.Z", "application/x-tarz"},
	{".tgz", "application/gzip"},
	{".tiff", "image/tiff"},
	{".txt", "text/plain"},
	{".wav", "audio/x-wav"},
	{".wmv", "video/x-ms-wm"},
	{".xbm", "image/x-xbitmap"},
	{".xml", "text/xml"},
	{".zip", "application/zip"},
	{".zoo", "application/x-zoo"},
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
	"416 Requested Range Not Satisfiable",
	"500 Internal Server Error",
	"501 Not Implemented",
	"503 Service Unavailable"
};


bool operator<(const inode &i1, const inode &i2)
{
	return memcmp(&i1, &i2, sizeof(i1)) < 0;
}


const char *lonely::why()
{
	return err.c_str();
}


int lonely::init(const string &host, const string &port, int a)
{
	cur_time = time(NULL);

	af = a;

	int sock_fd = socket(af, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		err = "lonely::init::socket:";
		err += strerror(errno);
		return -1;
	}

	// bind & listen
	if (bind_local(sock_fd, host, port, 1, af) < 0) {
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

	fd2state = new (nothrow) struct status*[rl.rlim_cur];
	if (!fd2state) {
		err = "loneley::init::OOM";
		return -1;
	}
	memset(fd2state, 0, rl.rlim_cur*sizeof(struct status*));

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


void lonely::shutdown(int fd)
{
	if (fd < 0)
		return;
	if (!fd2state[fd])
		return;

	::shutdown(fd, SHUT_RDWR);
	fd2state[fd]->state = STATE_CLOSING;
}


void lonely::cleanup(int fd)
{
	if (fd < 0)
		return;

	pfds[fd].fd = -1;
	pfds[fd].events = pfds[fd].revents = 0;
	close(fd);

	if (fd2state[fd]) {
		fd2state[fd]->peer_fd = -1;
		fd2state[fd]->path.clear();
		fd2state[fd]->state = STATE_NONE;
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


int lonely_http::loop()
{
	int i = 0;
#ifndef linux
	int flags = O_RDWR;
#endif
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	socklen_t slen = sizeof(sin);
	struct sockaddr *saddr = (struct sockaddr *)&sin;
	struct tm tm;
	struct timeval tv;

	if (af == AF_INET6) {
		slen = sizeof(sin6);
		saddr = (struct sockaddr *)&sin6;
	}

	for (;;) {
		// 0 means timeout which we also need to handle
		if (poll(pfds, max_fd + 1, 3*1000) < 0)
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
			if (!fd2state[i] || fd2state[i]->state == STATE_NONE)
				continue;

			// more than 30s no data?! But don't time out accept socket.
			if (fd2state[i]->state != STATE_ACCEPTING &&
			    cur_time - fd2state[i]->alive_time > timeout_alive) {
				if (pfds[i].revents == 0) {
					cleanup(i);
					continue;
				}
			}
			if (fd2state[i]->state == STATE_CLOSING &&
			    cur_time - fd2state[i]->alive_time > timeout_closing) {
				cleanup(i);
				continue;
			}

			if (pfds[i].revents == 0)
				continue;

			if ((pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
				cleanup(i);
				continue;
			}

			cur_peer = i;
			fd2state[i]->alive_time = cur_time;

			// All below states have an event pending, since we wont
			// be here if revents would be 0

			// new connection ready to accept?
			if (fd2state[i]->state == STATE_ACCEPTING) {
				pfds[i].revents = 0;
				pfds[i].events = POLLIN|POLLOUT;

				int afd = 0;
				for (;;) {
#ifdef linux
					afd = accept4(i, saddr, &slen, SOCK_NONBLOCK);
#else
					afd = accept(i, saddr, &slen);
#endif
					if (afd < 0) {
						if (errno == EMFILE || errno == ENFILE)
							clear_cache();
						break;
					}
					pfds[afd].fd = afd;
					pfds[afd].events = POLLIN;
					pfds[afd].revents = 0;
#ifndef linux
#ifndef GETFL_OPTIMIZATION
					flags = fcntl(afd, F_GETFL);
#endif
					fcntl(afd, F_SETFL, flags|O_NONBLOCK);
#endif

					// We reuse previously allocated but 'cleanup'ed memory to save
					// speed for lotsa new/delete calls on heavy traffic
					if (!fd2state[afd]) {
						fd2state[afd] = new (nothrow) struct status;

						if (!fd2state[afd]) {
							cleanup(afd);
							continue;
						}
					}

					fd2state[afd]->state = STATE_CONNECTED;
					fd2state[afd]->alive_time = cur_time;
					fd2state[afd]->sin = sin;
					fd2state[afd]->sin6 = sin6;

					if (afd > max_fd)
						max_fd = afd;
				}
				// There is nothing more to do for the accept socket;
				// just continue with the other sockets
				continue;
			} else if (fd2state[i]->state == STATE_CONNECTED) {
				if (handle_request() < 0) {
					cleanup(i);
					continue;
				}
			} else if (fd2state[i]->state == STATE_CLOSING) {
				cleanup(i);
				continue;
			} else if (fd2state[i]->state == STATE_TRANSFERING) {
				if (transfer() < 0) {
					cleanup(i);
					continue;
				}
			}

			// do not glue together the above and below if()'s because
			// transfer() may change state so we need a 2nd state-engine walk

			// In case of TRANSFERING we have data to send, so POLLOUT.
			if (fd2state[i]->state == STATE_TRANSFERING) {
				pfds[i].events = POLLOUT;
			} else if (fd2state[i]->state == STATE_CONNECTED)
				pfds[i].events = POLLIN;

			if (!fd2state[i]->keep_alive && fd2state[i]->state == STATE_CONNECTED) {
				pfds[i].events = POLLIN;
				shutdown(i);
			}
			pfds[i].revents = 0;
		}
		calc_max_fd();
	}
	return 0;
}


// In which timeframe complete header must arrive after 1st byte received
const uint8_t lonely_http::timeout_header = 3;

// timeout between shutdown() and close()
const uint8_t lonely::timeout_closing = 3;

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


int lonely_http::send_http_header()
{
	string http_header;

	if (cur_range_requested) {
		http_header = "HTTP/1.1 206 Partial Content\r\nServer: lophttpd\r\n";
		char range[256];
		snprintf(range, sizeof(range), "Content-Range: bytes %zu-%zu/%zu\r\nDate: ",
		         cur_start_range, cur_end_range - 1, cur_stat.st_size);
		http_header += range;
	} else
		http_header = "HTTP/1.1 200 OK\r\nServer: lophttpd\r\nDate: ";
	http_header += gmt_date;
	http_header += "\r\nContent-Type: %s\r\n"
	               "Content-Length: %zu\r\n\r\n";

	char h_buf[http_header.size() + 128];
	snprintf(h_buf, sizeof(h_buf), http_header.c_str(),
	          content_types[fd2state[cur_peer]->ct].c_type.c_str(), fd2state[cur_peer]->left);

	if (writen(cur_peer, h_buf, strlen(h_buf)) <= 0)
		return -1;

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

	const string &p = fd2state[cur_peer]->path;
	size_t l = http_header.size() + 128 + NS_Misc::dir2index[p].size();
	char *h_buf = new (nothrow) char[l];
	if (!h_buf)
		return 0;
	snprintf(h_buf, l, http_header.c_str(), NS_Misc::dir2index[p].size(),
	         NS_Misc::dir2index[p].c_str());
	int r = writen(cur_peer, h_buf, strlen(h_buf));
	delete [] h_buf;

	if (r <= 0)
		return -1;

	return r;
}


int lonely_http::transfer()
{
	int fd = open();
	if (fd < 0) {
		err = "lonely_http::transfer::open:";
		err += strerror(errno);
		return -1;
	}

	// send prefix header if nothing has been sent so far
	if (fd2state[cur_peer]->copied == 0) {
		if (send_http_header() < 0)
			return -1;
	}

	size_t n = fd2state[cur_peer]->left;
	if (n > mss)
		n = mss;

#ifdef linux
	ssize_t r = sendfile(cur_peer, fd, &fd2state[cur_peer]->offset, n);
	if (r > 0) {
		fd2state[cur_peer]->left -= r;
		fd2state[cur_peer]->copied += r;
	}
#else
// FreeBSD tested at least
	off_t sbytes = 0;
	ssize_t r = sendfile(fd, cur_peer, fd2state[cur_peer]->offset, n,
	                     NULL, &sbytes, 0);
	if (sbytes > 0) {
		fd2state[cur_peer]->offset += sbytes;
		fd2state[cur_peer]->left -= sbytes;
		fd2state[cur_peer]->copied += sbytes;
	}
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
		fd2state[cur_peer]->state = STATE_CONNECTED;
		fd2state[cur_peer]->keep_alive = 0;
		return -1;
	} else if (fd2state[cur_peer]->left == 0) {
		//close(pf.fd); Do not close, due to caching
		fd2state[cur_peer]->state = STATE_CONNECTED;
		fd2state[cur_peer]->header_time  = 0;
	} else {
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
	if (af == AF_INET)
		inet_ntop(AF_INET, &fd2state[cur_peer]->sin.sin_addr, dst, sizeof(dst));
	else
		inet_ntop(AF_INET6, &fd2state[cur_peer]->sin6.sin6_addr, dst, sizeof(dst));

	prefix += ": ";
	prefix += dst;
	prefix += ": ";
	prefix += msg;
	logger->log(prefix);
}


int lonely_http::HEAD()
{
	string head;
	char content[128];
	size_t cl = 0;

	string logstr = "HEAD ";
	logstr += fd2state[cur_peer]->path;
	logstr += "\n";
	log(logstr);

	if (de_escape_path() < 0)
		return send_error(HTTP_ERROR_400);

	if (stat() < 0)
		head = "HTTP/1.1 404 Not Found\r\nDate: ";
	else {
		head = "HTTP/1.1 200 OK\r\n";

		if (S_ISDIR(cur_stat.st_mode)) {
			string o_path = fd2state[cur_peer]->path;
			fd2state[cur_peer]->path += "/index.html";
			if (stat() == 0)
				cl = cur_stat.st_size;
			else {
				map<string, string>::iterator i = NS_Misc::dir2index.find(o_path);
				if (i == NS_Misc::dir2index.end())
					cl = 0;
				else {
					cl = i->second.size();
					// override content-type to text/html as we know it know
					fd2state[cur_peer]->ct = 1;
				}

				// Not needed, since request is finished here
				//fd2state[cur_peer]->path = o_path;
			}
			head += "Accept-Ranges: none\r\nDate: ";
		} else {
			cl = cur_stat.st_size;
			if (fd2state[cur_peer]->path.find(".html") != string::npos ||
		    	    fd2state[cur_peer]->path.find(".htm") != string::npos)
				head += "Accept-Ranges: none\r\nDate: ";
			else
				head += "Accept-Ranges: bytes\r\nDate: ";
		}
	}

	head += gmt_date;
	snprintf(content, sizeof(content), "\r\nContent-Length: %zu\r\nContent-Type: ", cl);
	head += content;
	head += content_types[fd2state[cur_peer]->ct].c_type;
	head += "\r\nServer: lophttpd\r\nConnection: keep-alive\r\n\r\n";

	if (writen(cur_peer, head.c_str(), head.size()) <= 0)
		return -1;
	return 0;
}


int lonely_http::OPTIONS()
{
	string reply = "HTTP/1.1 200 OK\r\nDate: ";
	reply += gmt_date;
	reply += "\r\nServer: lophttpd\r\nContent-Length: 0\r\nAllow: OPTIONS, GET, HEAD, POST\r\n\r\n";
	log("OPTIONS\n");
	if (writen(cur_peer, reply.c_str(), reply.size()) <= 0)
		return -1;
	return 0;
}


int lonely_http::DELETE()
{
	log("DELETE\n");
	return send_error(HTTP_ERROR_405);
}


int lonely_http::CONNECT()
{
	log("CONNECT\n");
	return send_error(HTTP_ERROR_405);
}


int lonely_http::TRACE()
{
	log("TRACE\n");
	return send_error(HTTP_ERROR_501);
}


int lonely_http::PUT()
{
	log("PUT\n");
	return send_error(HTTP_ERROR_405);
}



int lonely_http::POST()
{
	return GETPOST();
}


// for sighandler if new files appear in webroot
void lonely_http::clear_cache()
{
	stat_cache.clear();

	map<inode, int> dont_close;

	// do not close files in transfer
	for (int i = 0; i <= max_fd; ++i) {
		if (fd2state[i]) {
			if (fd2state[i]->state == STATE_TRANSFERING) {
				inode ino = {fd2state[i]->dev, fd2state[i]->ino};
				dont_close[ino] = 1;
			}
		}
	}

	for (map<inode, int>::iterator it = file_cache.begin(); it != file_cache.end();) {
		if (dont_close.find(it->first) == dont_close.end()) {
			close(it->second);
			file_cache.erase(it);
			it = file_cache.begin();
			continue;
		}
		++it;
	}
}


int lonely_http::stat()
{
	const string &p = fd2state[cur_peer]->path;
	int r = 0, ct = 0, i = 0;
	bool cacheit = 0;

	// do not cache stupid filenames which most likely is an attack
	// to exhaust our cache memory with combinations of ..//../foo etc.
	if (p.find("..") == string::npos)
		if (p.find("//") == string::npos)
			cacheit = 1;

	map<string, pair<struct stat, int> >::iterator it;

	fd2state[cur_peer]->ct = 0;

	if (!cacheit) {
		r = ::stat(p.c_str(), &cur_stat);
	} else {
		it = stat_cache.find(p);
		if (it != stat_cache.end()) {
			cur_stat = it->second.first;
			ct = it->second.second;
			cacheit = 0;
		} else {
			r = ::stat(p.c_str(), &cur_stat);
			if (r < 0)
				return r;

			// text/html if in generated index
			if (S_ISDIR(cur_stat.st_mode) &&
			    NS_Misc::dir2index.find(p) != NS_Misc::dir2index.end())
				ct = 1;
			else {
				// Not cached, so lets also find out about the content-type
				for (i = 0; !content_types[i].extension.empty(); ++i) {
					if (p.size() <= content_types[i].extension.size())
						continue;
					if (strcasestr(p.c_str()+p.size() - content_types[i].extension.size(),
				        	       content_types[i].extension.c_str()))
						break;
				}
				if (!content_types[i].c_type.empty())
					ct = i;
			}
		}
	}

	if (r == 0) {
		fd2state[cur_peer]->dev = cur_stat.st_dev;
		fd2state[cur_peer]->ino = cur_stat.st_ino;
		fd2state[cur_peer]->ct = ct;
		if (cacheit)
			stat_cache[p] = make_pair<struct stat, int>(cur_stat, ct);
	}

	return r;
}


// special caching open. before calling open(), you have to have
// called stat() in order to have valid dev/ino pair. This aint a
// problem since one needs to call stat() beforehand anyways
// for content-length etc.
int lonely_http::open()
{
	int fd = -1;

	struct inode i = {fd2state[cur_peer]->dev, fd2state[cur_peer]->ino};

	map<inode, int>::iterator it = file_cache.find(i);
	if (it != file_cache.end()) {
		fd = it->second;
	} else {
		fd = ::open(fd2state[cur_peer]->path.c_str(), O_RDONLY);
		if (fd >= 0) {
			file_cache[i] = fd;
		// Too many open files? Drop caches
		} else if (errno == EMFILE || errno == ENFILE) {
			clear_cache();
			fd = ::open(fd2state[cur_peer]->path.c_str(), O_RDONLY);
			if (fd >= 0)
				file_cache[i] = fd;
		}
	}
	return fd;
}


int lonely_http::de_escape_path()
{
	string &p = fd2state[cur_peer]->path;
	if (p.find("%") == string::npos)
		return 0;

	string tmp;
	tmp.resize(16);
	size_t pos = 0;
	unsigned char c = 0, c1, c2;
	tmp = "";
	while ((pos = p.find("%")) != string::npos) {
		// must have at least 2 chars after % escape
		if (pos > p.size() - 3)
			return -1;
		if (!isxdigit(p[pos + 1]) || !isxdigit(p[pos + 2]))
			return -1;
		c1 = toupper(p[pos + 1]);
		c2 = toupper(p[pos + 2]);
		if (c1 >= 'A' && c1 <= 'F')
			c = (10 + c1 - 'A')<<4;
		else
			c = (c1 - '0')<<4;
		if (c2 >= 'A' && c2 <= 'F')
			c += (10 + c2 - 'A');
		else
			c += (c2 - '0');
		tmp.push_back(c);
		p.replace(pos, 3, tmp, 0, 1);
		tmp = "";
	}
	return 0;
}


int lonely_http::GETPOST()
{
	string logstr;

	if (cur_request == HTTP_REQUEST_GET) {
		logstr = "GET ";
	} else {
		logstr = "POST ";
	}

	logstr += fd2state[cur_peer]->path;
	logstr += "\n";
	log(logstr);

	if (de_escape_path() < 0)
		return send_error(HTTP_ERROR_400);

	int r = 0;
	if ((r = stat()) == 0 && (S_ISREG(cur_stat.st_mode))) {
		if (cur_end_range == 0)
			cur_end_range = cur_stat.st_size;
		if (cur_start_range < 0 ||
		    cur_start_range >= cur_stat.st_size ||
		    cur_end_range > (size_t)cur_stat.st_size ||
		    (size_t)cur_start_range >= cur_end_range) {
			return send_error(HTTP_ERROR_416);
		}

		fd2state[cur_peer]->offset = cur_start_range;
		fd2state[cur_peer]->copied = 0;
		fd2state[cur_peer]->left = cur_end_range - cur_start_range;

		if (transfer() < 0)
			return send_error(HTTP_ERROR_404);
	} else if (r == 0 && S_ISDIR(cur_stat.st_mode)) {
		// No Range: requests for directories
		if (cur_range_requested)
			return send_error(HTTP_ERROR_416);
		string o_path = fd2state[cur_peer]->path;
		// index.html exists? send!
		fd2state[cur_peer]->path += "/index.html";
		if (stat() == 0 && (S_ISREG(cur_stat.st_mode))) {
			fd2state[cur_peer]->offset = 0;
			fd2state[cur_peer]->copied = 0;
			fd2state[cur_peer]->left = cur_stat.st_size;
			if (transfer() < 0)
				return send_error(HTTP_ERROR_404);
		} else {
			fd2state[cur_peer]->path = o_path;
			if (send_genindex() < 0)
				return -1;
		}
	} else {
		return send_error(HTTP_ERROR_404);
	}

	return 0;
}


int lonely_http::GET()
{
	return GETPOST();
}


int lonely_http::send_error(http_error_code_t e)
{
	string http_header = "HTTP/1.1 ";

	if (e >= HTTP_ERROR_END)
		e = HTTP_ERROR_400;
	http_header += http_error_msgs[e];
	http_header += "\r\nServer: lophttpd\r\nDate: ";
	http_header += gmt_date;

	if (e == HTTP_ERROR_405)
		http_header += "\r\nAllow: OPTIONS, GET, HEAD, POST";

	http_header += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	fd2state[cur_peer]->keep_alive = 0;

	if (writen(cur_peer, http_header.c_str(), http_header.size()) <= 0)
		return -1;

	shutdown(cur_peer);
	return 0;
}


int lonely_http::handle_request()
{
	char req_buf[2048], *ptr = NULL, *ptr2 = NULL, *end_ptr = NULL,
	     *last_byte = &req_buf[sizeof(req_buf) - 1], body[2048];
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
			return send_error(HTTP_ERROR_400);
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

	fd2state[cur_peer]->keep_alive = 0;
	int (lonely_http::*action)() = NULL;

	cur_request = HTTP_REQUEST_NONE;
	cur_start_range = cur_end_range = 0;
	cur_range_requested = 0;

	// Have the most likely request type first to skip needless
	// compares
	if (strncasecmp(req_buf, "GET", 3) == 0) {
		action = &lonely_http::GET;
		cur_request = HTTP_REQUEST_GET;
		ptr = req_buf + 3;

	// For POST requests, we also require a Content-Length that matches.
	// The above if() already ensured we have header until "\r\n\r\n"
	} else if (strncmp(req_buf, "POST", 4) == 0) {
		if ((ptr = strcasestr(req_buf, "Content-Length:")) != NULL) {
			ptr += 15;
			for (;ptr < end_ptr; ++ptr) {
				if (*ptr != ' ')
					break;
			}
			if (ptr >= end_ptr)
				return send_error(HTTP_ERROR_400);
			size_t cl = strtoul(ptr, NULL, 10);
			if (cl >= sizeof(body))
				return send_error(HTTP_ERROR_414);
			// The body should be right here, we dont mind if stupid senders
			// send them separately
			if ((size_t)recv(cur_peer, body, sizeof(body), MSG_DONTWAIT) != cl)
				return send_error(HTTP_ERROR_400);
		} else {
			return send_error(HTTP_ERROR_411);
		}
		action = &lonely_http::POST;
		cur_request = HTTP_REQUEST_POST;
		ptr = req_buf + 4;
	} else if (strncasecmp(req_buf, "OPTIONS", 7) == 0) {
		action = &lonely_http::OPTIONS;
		cur_request = HTTP_REQUEST_OPTIONS;
		ptr = req_buf + 7;
	} else if (strncasecmp(req_buf, "HEAD", 4) == 0) {
		action = &lonely_http::HEAD;
		cur_request = HTTP_REQUEST_HEAD;
		ptr = req_buf + 4;
	} else if (strncasecmp(req_buf, "PUT", 3) == 0) {
		action = &lonely_http::PUT;
		cur_request = HTTP_REQUEST_PUT;
		ptr = req_buf + 3;
	} else if (strncasecmp(req_buf, "DELETE", 6) == 0) {
		action = &lonely_http::DELETE;
		cur_request = HTTP_REQUEST_DELETE;
		ptr = req_buf + 6;
	} else if (strncasecmp(req_buf, "TRACE", 5) == 0) {
		action = &lonely_http::TRACE;
		cur_request = HTTP_REQUEST_TRACE;
		ptr = req_buf + 5;
	} else if (strncasecmp(req_buf, "CONNECT", 7) == 0) {
		action = &lonely_http::CONNECT;
		cur_request = HTTP_REQUEST_CONNECT;
		ptr = req_buf + 7;
	} else {
		return send_error(HTTP_ERROR_400);
	}

	for (; ptr < end_ptr; ++ptr) {
		if (*ptr != ' ')
			break;
	}

	if (ptr >= end_ptr)
		return send_error(HTTP_ERROR_400);

	end_ptr = ptr + strcspn(ptr + 1, "? \t\r");

	if (end_ptr >= last_byte)
		return send_error(HTTP_ERROR_400);
	end_ptr[1] = 0;

	fd2state[cur_peer]->path = ptr;

	ptr = end_ptr + 2; // rest of header
	if (ptr > last_byte)
		return send_error(HTTP_ERROR_400);

	if ((ptr2 = strcasestr(ptr, "Connection:")) && cur_peer < 30000) {
		ptr2 += 11;
		for (;ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}
		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400);

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

		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400);

		if ((end_ptr = strcasestr(ptr2, "\r\n"))) {

			*end_ptr = 0;

			// Not a security issue, but makes no sense
			if (string(ptr2) == "icons")
				return send_error(HTTP_ERROR_404);

			// If already requesting vhost files (genindex), then, do not prepend
			// vhost path again
			if (!strstr(fd2state[cur_peer]->path.c_str(), "vhost")) {
				string tmps = fd2state[cur_peer]->path;
				fd2state[cur_peer]->path = "/vhost";
				fd2state[cur_peer]->path += ptr2;
				if (tmps != "/")
					fd2state[cur_peer]->path += tmps;
			}
		} else {
			return send_error(HTTP_ERROR_400);
		}

	}

	// Range: bytes 0-7350
	if ((ptr2 = strcasestr(ptr, "Range:")) != NULL) {
		if (cur_request != HTTP_REQUEST_GET)
			return send_error(HTTP_ERROR_416);

		ptr2 += 6;
		for (; ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}
		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400);
		if (strncmp(ptr2, "bytes=", 6) != 0)
			return send_error(HTTP_ERROR_416);
		ptr2 += 6;
		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400);
		end_ptr = NULL;
		cur_start_range = strtoul(ptr2, &end_ptr, 10);
		if (!end_ptr || end_ptr == ptr2 || end_ptr + 1 >= last_byte)
			return send_error(HTTP_ERROR_400);
		char *end_ptr2 = NULL;
		cur_end_range = strtoul(end_ptr + 1, &end_ptr2, 10);
		if (!end_ptr2 || end_ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400);
		// dont accept further ranges, one is enough
		if (*end_ptr2 != '\r')
			return send_error(HTTP_ERROR_416);

		// Range: is from first byte to last byte _inclusive_; will be subtracted
		// in header reply later then
		if (cur_end_range)
			++cur_end_range;
		cur_range_requested = 1;
	}

	return (this->*action)();
}

