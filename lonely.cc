/*
 * Copyright (C) 2008-2013 Sebastian Krahmer.
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
#include <ctype.h>
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
#include "rproxy.h"
#include "misc.h"
#include "socket.h"
#include "flavor.h"
#include "client.h"

#ifdef USE_SSL
extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}
#endif

using namespace std;
using namespace ns_socket;


// Must match order of http_error_code_t enum
string http_error_msgs[] = {
	"400 Bad Request",
	"401 Unauthorized",
	"404 Not Found",
	"405 Method Not Allowed",
	"406 Not Acceptable",
	"408 Request Time-out",
	"411 Length Required",
	"414 Request-URI Too Large",
	"416 Requested Range Not Satisfiable",
	"500 Internal Server Error",
	"501 Not Implemented",
	"503 Service Unavailable"
};

const string lonely_http::hdr_fmt =
	"HTTP/1.1 200 OK\r\n"
	"Server: lophttpd\r\n"
	"Date: %s\r\n"
	"Content-Length: %zu\r\n"
	"Content-Type: %s\r\n\r\n";

const string lonely_http::chunked_hdr_fmt =
	"HTTP/1.1 200 OK\r\n"
	"Server: lophttpd\r\n"
	"Date: %s\r\n"
	"Transfer-Encoding: chunked\r\n"
	"Content-Type: %s\r\n\r\n";

const string lonely_http::part_hdr_fmt =
	"HTTP/1.1 206 Partial Content\r\n"
	"Server: lophttpd\r\n"
	"Date: %s\r\n"
	"Content-Length: %zu\r\n"
	"Content-Type: %s\r\n"
	"Content-Range: bytes %zu-%zu/%zu\r\n\r\n";

const string lonely_http::put_hdr_fmt =
	"HTTP/1.1 201 Created\r\n"
	"Server: lophttpd\r\n"
	"Date: %s\r\n"
	"Content-Length: %zu\r\n"
	"Content-Type: text/html\r\n\r\n";

bool operator<(const inode &i1, const inode &i2)
{
	return memcmp(&i1, &i2, sizeof(i1)) < 0;
}


template<typename state_engine>
const char *lonely<state_engine>::why()
{
	return err.c_str();
}


template<typename state_engine>
int lonely<state_engine>::init(const string &host, const string &port, int a)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	cur_time = tv.tv_sec;
	cur_usec = tv.tv_usec;

	af = a;

	int sock_fd = socket(af, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		err = "lonely::init::socket:";
		err += strerror(errno);
		return -1;
	}

	// bind & listen
	if (bind_local(sock_fd, host, port, 1, af) < 0) {
		err = ns_socket::why();
		return -1;
	}

	socklen_t olen = sizeof(so_sndbuf);
	getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf, &olen);

	// allocate poll array
	struct rlimit rl;
	rl.rlim_cur = (1<<18);
	rl.rlim_max = rl.rlim_cur;

	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		rl.rlim_cur = (1<<16);
		rl.rlim_max = rl.rlim_cur;
		if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
			if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
				err = "lonely::init::getrlimit:";
				err += strerror(errno);
				return -1;
			}
		}
	}

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	fd2peer = new (nothrow) state_engine*[rl.rlim_cur];
	if (!fd2peer) {
		err = "loneley::init::OOM";
		return -1;
	}
	memset(fd2peer, 0, rl.rlim_cur*sizeof(state_engine *));

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

	fd2peer[sock_fd] = new state_engine;
	fd2peer[sock_fd]->transition(STATE_ACCEPTING);
	fd2peer[sock_fd]->keep_alive = 1;
	fd2peer[sock_fd]->peer_fd = sock_fd;


	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	return 0;
}


template<typename state_engine>
void lonely<state_engine>::shutdown(int fd)
{
	if (fd < 0)
		return;
	if (!fd2peer[fd])
		return;

	// might be called twice or again after close() if peer has an issue
	if (fd2peer[fd]->state() == STATE_CLOSING || fd2peer[fd]->state() == STATE_NONE)
		return;

	if (fd2peer[fd]->state() == STATE_UPLOADING)
		close(fd2peer[fd]->file_fd);

	::shutdown(fd, SHUT_RDWR);

	fd2peer[fd]->transition(STATE_CLOSING);
	fd2peer[fd]->blen = 0;

	pfds[fd].fd = -1;
	pfds[fd].events = pfds[fd].revents = 0;

	// do not set peer_fd to -1, as send_error() in proxy calls shutdown()
	// and we dont have any reference to peer anymore but need to call clenup()
	// on the peer
}


template<typename state_engine>
void lonely<state_engine>::cleanup(int fd)
{
	if (fd < 0)
		return;

	pfds[fd].fd = -1;
	pfds[fd].events = pfds[fd].revents = 0;
	close(fd);

	if (n_clients > 0)
		--n_clients;

	if (fd2peer[fd])
		fd2peer[fd]->cleanup();

	if (max_fd == fd)
		--max_fd;
}


template<typename state_engine>
void lonely<state_engine>::calc_max_fd()
{
	// find the highest fd that is in use
	for (int i = max_fd; i >= first_fd; --i) {
		if (fd2peer[i] && fd2peer[i]->state() != STATE_NONE) {
			max_fd = i;
			return;
		}
		if (pfds[i].fd != -1) {
			max_fd = i;
			return;
		}
	}
}


template<typename state_engine>
int lonely<state_engine>::open_log(const string &logfile, const string &method, int core = 0)
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


template<typename state_engine>
void lonely<state_engine>::log(const string &msg)
{
	// in quiet mode, logger is NULL
	if (!logger)
		return;

	string prefix = local_date;

	if (peer_idx >= 0 && fd2peer[peer_idx] != NULL) {
		prefix += ": ";
		prefix += fd2peer[peer_idx]->from_ip;
		prefix += ": ";
	} else
		prefix += ": <no client context>: ";

	prefix += msg;
	if (msg.c_str()[msg.size() - 1] != '\n')
		prefix += "\n";

	logger->log(prefix);
}



int lonely_http::setup_ssl(const string &cpath, const string &kpath)
{

#ifdef USE_SSL
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	if ((ssl_method = TLSv1_server_method()) == NULL) {
		err = "lonely_http::setup_ssl::TLSv1_server_method:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	if ((ssl_ctx = SSL_CTX_new(ssl_method)) == NULL) {
		err = "lonely_http::setup_ssl::SSL_CTX_new:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (SSL_CTX_use_certificate_file(ssl_ctx, cpath.c_str(), SSL_FILETYPE_PEM) != 1) {
		err = "lonely_http::setup_ssl::SSL_CTX_use_certificate_file:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, kpath.c_str(), SSL_FILETYPE_PEM) != 1) {
		err = "lonely_http::setup_ssl::SSL_CTX_use_PrivateKey_file:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		err = "lonely_http::setup_ssl::SSL_CTX_check_private_key:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (SSL_CTX_set_session_id_context(ssl_ctx, (const unsigned char *)"lophttpd", 8) != 1) {
		err = "lonely_http::setup_ssl::SSL_CTX_set_session_id_context:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

	SSL_CTX_sess_set_new_cb(ssl_ctx, http_client::new_session);
	SSL_CTX_sess_set_remove_cb(ssl_ctx, http_client::remove_session);
	SSL_CTX_sess_set_get_cb(ssl_ctx, http_client::get_session);

#endif

	return 0;
}



int lonely_http::loop()
{
	int i = 0, r = 0;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	socklen_t slen = sizeof(sin);
	struct sockaddr *saddr = (struct sockaddr *)&sin;
	struct tm tm;
	struct timeval tv;
	char from[128];


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

		// optimization: only stringify time if at least 1s elapsed
		if (cur_time != tv.tv_sec) {
			cur_time = tv.tv_sec;
			cur_usec = tv.tv_usec;

			localtime_r(&cur_time, &tm);
			strftime(local_date, sizeof(local_date), "%a, %d %b %Y %H:%M:%S GMT%z", &tm);
			gmtime_r(&cur_time, &tm);
			strftime(gmt_date, sizeof(gmt_date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
		}

		for (i = first_fd; i <= max_fd; ++i) {

			// this check must come first, as pfds[i].fd is already -1 in
			// STATE_CLOSING
			if (fd2peer[i] && fd2peer[i]->state() == STATE_CLOSING) {
				if (heavy_load || (cur_time - fd2peer[i]->alive_time > TIMEOUT_CLOSING))
					cleanup(i);
				continue;
			}

			if (pfds[i].fd == -1)
				continue;
			if (!fd2peer[i] || fd2peer[i]->state() == STATE_NONE)
				continue;

			peer = fd2peer[i];
			peer_idx = i;

			// more than 30s no data?! But don't time out accept socket.
			if (peer->state() != STATE_ACCEPTING &&
			    cur_time - peer->alive_time > TIMEOUT_ALIVE) {
				cleanup(i);
				continue;
			}

			if (pfds[i].revents == 0 && peer->state() != STATE_DOWNLOADING_FULL)
				continue;

			if ((pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
				cleanup(i);
				continue;
			}

			// All below states have an event pending, since we wont
			// be here if revents would be 0

			// new connection ready to accept?
			if (peer->state() == STATE_ACCEPTING) {
				pfds[i].revents = 0;
				pfds[i].events = POLLIN|POLLOUT;
				peer->alive_time = cur_time;

				int afd = 0;
				for (;n_clients < httpd_config::max_connections;) {
					heavy_load = 0;
					afd = flavor::accept(i, saddr, &slen, flavor::NONBLOCK);
					if (afd < 0) {
						if (errno == EMFILE || errno == ENFILE) {
							heavy_load = 1;
							clear_cache();
						}
						break;
					}

					pfds[afd].fd = afd;
					pfds[afd].events = POLLIN;
					pfds[afd].revents = 0;

					// We reuse previously allocated but 'cleanup'ed memory to save
					// speed for lotsa new/delete calls on heavy traffic
					if (!fd2peer[afd]) {
						fd2peer[afd] = new (nothrow) struct http_client;

						if (!fd2peer[afd]) {
							cleanup(afd);
							continue;
						}
					}

					if (httpd_config::use_ssl)
						fd2peer[afd]->transition(STATE_HANDSHAKING);
					else
						fd2peer[afd]->transition(STATE_CONNECTED);

					fd2peer[afd]->alive_time = cur_time;
					fd2peer[afd]->peer_fd = afd;

					if (af == AF_INET)
						inet_ntop(AF_INET, &sin.sin_addr, from, sizeof(from));
					else
						inet_ntop(AF_INET6, &sin6.sin6_addr, from, sizeof(from));

					fd2peer[afd]->from_ip = from;

					if (afd > max_fd)
						max_fd = afd;
					++n_clients;
				}

				// There is nothing more to do for the accept socket;
				// just continue with the other sockets
				continue;
#ifdef USE_SSL
			} else if (peer->state() == STATE_HANDSHAKING) {
				if ((r = peer->ssl_accept(ssl_ctx)) < 0) {
					cleanup(i);
					continue;
				} else if (r > 0)
					peer->alive_time = cur_time;
#endif
			} else if (peer->state() == STATE_CONNECTED) {
				if ((r = handle_request()) < 0) {
					cleanup(i);
					continue;
				} else if (r > 0)
					peer->alive_time = cur_time;
			} else if (peer->state() == STATE_DOWNLOADING) {
				if ((r = download()) < 0) {
					cleanup(i);
					continue;
				} else if (r > 0)
					peer->alive_time = cur_time;
			} else if (peer->state() == STATE_UPLOADING) {
				if ((r = upload()) < 0) {
					cleanup(i);
					continue;
				} else if (r > 0)
					peer->alive_time = cur_time;
			}

			// do not glue together the above and below if()'s because
			// download() may change state so we need a 2nd state-engine walk

			switch (peer->state()) {
			case STATE_DOWNLOADING_FULL:
				if (!pfds[i].events && flavor::in_send_queue(i) == 0) {
					peer->alive_time = cur_time;
					pfds[i].events = POLLOUT;
					peer->transition(STATE_DOWNLOADING);
					--n_suspended;
				} else
					pfds[i].events = 0;
				break;
			case STATE_DOWNLOADING:
				pfds[i].events = POLLOUT;
				break;
			case STATE_UPLOADING:
			case STATE_CONNECTED:
			case STATE_HANDSHAKING:
				pfds[i].events = POLLIN;
				break;
			default:
				;
			}

			if (!peer->keep_alive && peer->state() == STATE_CONNECTED)
				shutdown(i);

			pfds[i].revents = 0;
		}
		calc_max_fd();
	}
	return 0;
}


int lonely_http::send_http_header()
{
	int l = 0;

	// partial content
	if (cur_range_requested) {
		l = snprintf(hbuf, sizeof(hbuf), part_hdr_fmt.c_str(),
	                     gmt_date, peer->left, misc::content_types[peer->ct].c_type.c_str(),
			     cur_start_range, cur_end_range - 1, cur_stat.st_size);
	// special regular file (proc or sys)
	} else if (peer->ftype == FILE_PROC) {
		l = snprintf(hbuf, sizeof(hbuf), chunked_hdr_fmt.c_str(),
		             gmt_date, "text/plain");
	} else {
		l = snprintf(hbuf, sizeof(hbuf), hdr_fmt.c_str(),
	                     gmt_date, peer->left, misc::content_types[peer->ct].c_type.c_str());
	}

	if (l < 0 || l > (int)sizeof(hbuf))
		return -1;

	int r = peer->send(hbuf, l);

	if (r != l)
		return -1;

	return r;
}


int lonely_http::send_genindex()
{
	const string &p = peer->path;
	string idx = "";

	map<string, string>::iterator i = misc::dir2index.find(p);
	if (i != misc::dir2index.end())
		idx = i->second;

	int l = snprintf(hbuf, sizeof(hbuf), hdr_fmt.c_str(), gmt_date, idx.size(), "text/html");
	if (l < 0 || l > (int)sizeof(hbuf))
		return -1;

	int r = peer->send(hbuf, l);

	if (r != l)
		return -1;

	r = peer->send(idx.c_str(), idx.size());

	if (r != (int)idx.size())
		return -1;

	return r;
}


int lonely_http::download()
{
	int r = 0;

	// First called on request?
	if (peer->state() == STATE_CONNECTED) {
		// assigns peer->file_fd
		if (open() < 0) {
			// callers of download() must not send_error() themself on -1,
			// as they cannot know whether a failure appeared before or after
			// send_header() call. Thus download() sends its erros themself.
			return send_error(HTTP_ERROR_500, -1);
		}
	}

	// send prefix header if nothing has been sent so far
	if (peer->copied == 0) {
		if (send_http_header() < 0)
			return -1;
	}

	if (!forced_send_size)
		n_send = DEFAULT_SEND_SIZE;

	if (!forced_send_size && peer->copied > 0 && n_clients > MANY_RECEIVERS) {
		if (httpd_config::client_sched == CLIENT_SCHED_NONE) {
				;
		} else if (httpd_config::client_sched == CLIENT_SCHED_MINIMIZE) {
			int not_sent = flavor::in_send_queue(peer->peer_fd);

			peer->in_queue = not_sent;

			if (not_sent > max_send)
				n_send = min_send;

			if (n_send > max_send)
				n_send = max_send;
			if (n_send < min_send)
				n_send = min_send;
		} else if (httpd_config::client_sched == CLIENT_SCHED_SUSPEND &&
		           n_clients - n_suspended > MANY_RECEIVERS) {
			int not_sent = flavor::in_send_queue(peer->peer_fd);

			peer->in_queue = not_sent;

			if (not_sent > max_send) {
				++n_suspended;
				peer->transition(STATE_DOWNLOADING_FULL);
				return 0;
			}
		} else if (httpd_config::client_sched == CLIENT_SCHED_STATIC) {
			n_send = DEFAULT_SEND_SIZE - 128*(n_clients/MANY_RECEIVERS);
			if (n_send < min_send || n_send > max_send)
				n_send = min_send;
		}
	}

	size_t n = peer->left;
	if (n > n_send)
		n = n_send;

	errno = 0;
	r = peer->sendfile(n);

	// Dummy reset of r, if EAGAIN appears on nonblocking socket
	// proc-files are written in chunks, so everything is lost anyway
	if (peer->ftype != FILE_PROC && errno == EAGAIN)
		r = 1;

	if (r < 0) {
		peer->transition(STATE_CONNECTED);
		peer->keep_alive = 0;
		return -1;
	} else if (peer->left == 0) {
		//close(pf.fd); Do not close, due to caching
		peer->file_fd = -1;
		peer->transition(STATE_CONNECTED);
	} else {
		peer->transition(STATE_DOWNLOADING);
	}

	return 1;
}



int lonely_http::HEAD()
{
	string head;
	char content[128];
	size_t cl = 0;
	string &p = peer->path;

	string logstr = "HEAD ";
	logstr += p;
	logstr += "\n";
	log(logstr);

	if (de_escape_path() < 0)
		return send_error(HTTP_ERROR_400, -1);

	if (stat() < 0)
		head = "HTTP/1.1 404 Not Found\r\nDate: ";
	else {
		head = "HTTP/1.1 200 OK\r\n";

		if (S_ISDIR(cur_stat.st_mode)) {
			map<string, string>::iterator i = misc::dir2index.find(p);
			if (i != misc::dir2index.end()) {
				cl = i->second.size();
			} else {
				p += "/index.html";
				if (stat() == 0)
					cl = cur_stat.st_size;
			}
			head += "Accept-Ranges: none\r\nDate: ";
		} else {
			cl = cur_stat.st_size;
			// No Range: for HTML
			if (peer->ct == misc::CONTENT_HTML)
				head += "Accept-Ranges: none\r\nDate: ";
			else
				head += "Accept-Ranges: bytes\r\nDate: ";
		}
	}

	head += gmt_date;
	snprintf(content, sizeof(content), "\r\nContent-Length: %zu\r\nContent-Type: ", cl);
	head += content;
	head += misc::content_types[peer->ct].c_type;
	head += "\r\nServer: lophttpd\r\nConnection: keep-alive\r\n\r\n";

	if (peer->send(head.c_str(), head.size()) != (int)head.size())
		return -1;
	return 1;
}


int lonely_http::OPTIONS()
{
	string reply = "HTTP/1.1 200 OK\r\nDate: ";
	reply += gmt_date;
	reply += "\r\nServer: lophttpd\r\nContent-Length: 0\r\nAllow: OPTIONS, GET, HEAD, POST, PUT\r\n\r\n";

	log("OPTIONS\n");
	if (peer->send(reply.c_str(), reply.size()) != (int)reply.size())
		return -1;
	return 1;
}


int lonely_http::DELETE()
{
	log("DELETE\n");
	return send_error(HTTP_ERROR_405, -1);
}


int lonely_http::CONNECT()
{
	log("CONNECT\n");
	return send_error(HTTP_ERROR_405, -1);
}


int lonely_http::TRACE()
{
	log("TRACE\n");
	return send_error(HTTP_ERROR_501, -1);
}


int lonely_http::upload()
{
	char buf[max_send];
	ssize_t n = 0;

	// upload file fd is closed via cleanup() in STATE_UPLOADING
	if ((n = peer->recv(buf, sizeof(buf))) <= 0)
		return send_error(HTTP_ERROR_400, -1);

	if (write(peer->file_fd, buf, n) != n)
		return send_error(HTTP_ERROR_500, -1);

	peer->copied += n;

	if (peer->copied == peer->left) {
		string html = "<html><body>File ";
		if (!httpd_config::rand_upload_quiet)
			html += peer->path;
		html += " was successfully uploaded.</body></html>\n";
		n = snprintf(buf, sizeof(buf), put_hdr_fmt.c_str(),
		         gmt_date, html.size());

		peer->send(buf, n);
		peer->send(html.c_str(), html.size());

		close(peer->file_fd);
		peer->file_fd = -1;
		peer->transition(STATE_CONNECTED);
		peer->keep_alive = 0;
	}

	return 1;
}


int lonely_http::PUT()
{
	string &p = peer->path;

	string logstr = "PUT ";
	logstr += p;
	logstr += "\n";
	log(logstr);

	if (p.find("..") != string::npos)
		return send_error(HTTP_ERROR_400, -1);

	int fd = 0;
	peer->offset = 0;
	peer->copied = 0;
	peer->left = peer->blen;

	if (httpd_config::rand_upload) {
		char rnd[64];
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		snprintf(rnd, sizeof(rnd), "-%08lx%08lx%08lx", cur_time, cur_usec, ts.tv_nsec);
		p += rnd;
	}

	if ((fd = ::open(p.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0)
		return send_error(HTTP_ERROR_400, -1);

	peer->file_fd = fd;
	peer->transition(STATE_UPLOADING);
	return 1;
}


int lonely_http::POST()
{
	return GETPOST();
}


// for sighandler if new files appear in webroot
void lonely_http::clear_cache()
{
	stat_cache.clear();
	err_cache.clear();

	map<inode, int> dont_close;

	// do not close files in transfer
	for (int i = 0; i <= max_fd; ++i) {
		if (fd2peer[i]) {
			if (fd2peer[i]->state() == STATE_DOWNLOADING) {
				inode ino = {fd2peer[i]->dev, fd2peer[i]->ino};
				dont_close[ino] = 1;
			}
		}
	}

	for (map<inode, int>::iterator it = file_cache.begin(); it != file_cache.end();) {
		if (dont_close.find(it->first) == dont_close.end()) {
			close(it->second);
			file_cache.erase(it++);
			continue;
		}
		++it;
	}
}


int lonely_http::stat()
{
	const string &p = peer->path;
	int r = 0, ct = misc::CONTENT_DATA;
	bool cacheit = 0;

	// do not cache stupid filenames which most likely is an attack
	// to exhaust our cache memory with combinations of ..//../foo etc.
	if (p.find("/../") == string::npos)
		if (p.find("///") == string::npos)
			if (p.find("/./") == string::npos)
				cacheit = 1;

	map<string, pair<struct stat, int> >::iterator it;

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

			// always text/html if dir, if theres no autoindexing,
			// the content-len will be 0
			if (S_ISDIR(cur_stat.st_mode))
				ct = misc::CONTENT_HTML;
			else
				ct = misc::find_ctype(p);
		}
	}

	if (r == 0) {
		if (!flavor::servable_file(cur_stat))
			return -1;

		// workaround for /proc and /sys files which are always reported 0 byte in size
		if (S_ISREG(cur_stat.st_mode) && cur_stat.st_blocks == 0) {
			peer->ftype = FILE_PROC;

		// special case for blockdevices; if not already fetched size,
		// put it into cur_stat
		} else if (flavor::servable_device(cur_stat)) {
			if (cur_stat.st_size == 0) {
				// updates size if apropriate
				size_t size;
				if (flavor::device_size(p, size) < 0)
					return -1;
				cur_stat.st_size = size;
				cacheit = 1;
			}
			ct = misc::CONTENT_DATA;
			peer->ftype = FILE_DEVICE;
		}
		peer->dev = cur_stat.st_dev;
		peer->ino = cur_stat.st_ino;
		peer->ct = ct;
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
	int flags = O_RDONLY|O_NOCTTY;
	struct inode i = {peer->dev, peer->ino};

	if (peer->ftype == FILE_PROC)
		flags |= O_NONBLOCK;

	map<inode, int>::iterator it = file_cache.find(i);
	if (it != file_cache.end()) {
		fd = it->second;
	} else {
		fd = ::open(peer->path.c_str(), flags);
		if (fd >= 0) {
			file_cache[i] = fd;
		// Too many open files? Drop caches
		} else if (errno == EMFILE || errno == ENFILE) {
			heavy_load = 1;
			clear_cache();
			fd = ::open(peer->path.c_str(), flags);
			if (fd >= 0)
				file_cache[i] = fd;
		}
	}

	peer->file_fd = fd;
	return fd;
}


int lonely_http::de_escape_path()
{
	string &p = peer->path;
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

	logstr += peer->path;
	logstr += "\n";
	log(logstr);

	if (de_escape_path() < 0)
		return send_error(HTTP_ERROR_404, -1);

	int r = 0, rr = 0;
	if ((r = stat()) == 0 && (S_ISREG(cur_stat.st_mode) || flavor::servable_device(cur_stat))) {
		if (cur_end_range == 0)
			cur_end_range = cur_stat.st_size;

		if (cur_range_requested) {
			if (cur_start_range < 0 ||
			    cur_start_range >= cur_stat.st_size ||
			    cur_end_range > (size_t)cur_stat.st_size ||
			    (size_t)cur_start_range >= cur_end_range) {
				return send_error(HTTP_ERROR_416, -1);
			}
		}

		peer->offset = cur_start_range;
		peer->copied = 0;
		peer->left = cur_end_range - cur_start_range;

		// proc files always report size 0
		if (peer->ftype == FILE_PROC)
			peer->left = 1024;

		rr = download();
	} else if (r == 0 && S_ISDIR(cur_stat.st_mode)) {
		// No Range: requests for directories
		if (cur_range_requested)
			return send_error(HTTP_ERROR_416, -1);
		if (misc::dir2index.count(peer->path) > 0) {
			rr = send_genindex();
		} else {
			// No generated index. Maybe index.html itself?
			peer->path += "/index.html";
			if (stat() == 0 && (S_ISREG(cur_stat.st_mode))) {
				peer->offset = 0;
				peer->copied = 0;
				peer->left = cur_stat.st_size;
				rr = download();
			} else
				return send_error(HTTP_ERROR_404, 0);
		}
	} else {
		return send_error(HTTP_ERROR_404, 0);
	}

	return rr;
}


int lonely_http::GET()
{
	return GETPOST();
}


int lonely_http::send_error(http_error_code_t e, int r)
{
	// If configured so, build up a cache of HTTP requests (as seen per
	// first line, e.g. "GET /foo") that caused errors in past. Inside
	// handle_request() we can save ressources to decode/parse/stat if the GET will
	// cause an error anyway.
	// Carefull! Only cache "Not found" so far, otherwise by sending buggy headers
	// attackers can overlay valid requests.
	if (httpd_config::ncache && e == HTTP_ERROR_404 && !vhosts) {
		if (err_cache.size() > httpd_config::ncache)
			err_cache.clear();
		if (peer->first_line.size() > 0)
			err_cache[peer->first_line] = e;
	}

	string http_header = "HTTP/1.1 ";

	if (e >= HTTP_ERROR_END)
		e = HTTP_ERROR_400;
	http_header += http_error_msgs[e];
	http_header += "\r\nServer: lophttpd\r\nDate: ";
	http_header += gmt_date;

	if (e == HTTP_ERROR_405)
		http_header += "\r\nAllow: OPTIONS, GET, HEAD, POST";

	if (!httpd_config::no_error_kill) {
		http_header += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
		peer->keep_alive = 0;
	} else
		http_header += "\r\nContent-Length: 0\r\n\r\n";

	if (peer->send(http_header.c_str(), http_header.size()) != (int)http_header.size()) {
		shutdown(peer_idx);
		return -1;
	}

	if (r < 0 || !httpd_config::no_error_kill)
		shutdown(peer_idx);

	return r;
}


int lonely_http::handle_request()
{
	char *ptr = NULL, *ptr2 = NULL, *end_ptr = NULL,
	     *last_byte = &peer->req_buf[sizeof(peer->req_buf) - 1], body[2048];
	int n;
	char *req_buf = peer->req_buf;

	// peek to find hopefully a complete header
	// this will also take off the data from a SSL socket if sent
	// as single bytes. Some browsers need so, and req_idx will say
	// which bytes have already been taken off net.

	n = peer->peek_req();

	// give partial SSL arived messages chance to complete
	if (n < 0 || (n == 0 && !peer->is_ssl())) {
		err = "lonely_http::handle_request::peek:";
		err += strerror(errno);
		return -1;
	}

	// If first read, set initial timestamp for header TO
	if (peer->header_time == 0)
		peer->header_time = cur_time;

	// incomplete header?
	if ((ptr = strstr(req_buf, "\r\n\r\n")) == NULL) {
		if (cur_time - peer->header_time > TIMEOUT_HEADER) {
			// even on no-error-kill, shutdown on timeout
			return send_error(HTTP_ERROR_408, -1);
		}
		peer->keep_alive = 1;
		return 0;
	}

	peer->header_time = 0;

	// should not happen, as req_idx is increased by one and checked for \r\n\r\n each
	// time
	if (peer->req_idx > (size_t)(ptr - req_buf + 4))
		return send_error(HTTP_ERROR_400, -1);

	n = 0;
	// read exactly the header from the queue, (if not already) including \r\n\r\n
	if (peer->req_idx < (size_t)(ptr - req_buf + 4)) {
		if ((n = peer->recv(req_buf + peer->req_idx, ptr - req_buf + 4 - peer->req_idx)) <= 0) {
			err = "lonely_http::handle_request::recv:";
			err += strerror(errno);
			return -1;
		}
	}

	end_ptr = req_buf + peer->req_idx + n;
	peer->req_idx = 0;

	peer->keep_alive = 1;
	int (lonely_http::*action)() = NULL;

	cur_request = HTTP_REQUEST_NONE;
	cur_start_range = cur_end_range = 0;
	cur_range_requested = 0;

	if (httpd_config::ncache) {
		if ((ptr = strchr(req_buf, '\n'))) {
			peer->first_line = string(req_buf, ptr - req_buf);
		}
		if (err_cache.count(peer->first_line) > 0) {
			return send_error(err_cache[peer->first_line], 0);
		}
	}

	// The above if() already ensured we have header until "\r\n\r\n"
	// Only PUT and POST require cl
	size_t cl = 0;
	if (req_buf[0] == 'P' && (ptr = strcasestr(req_buf, "\nContent-Length:")) != NULL) {
		ptr += 16;
		for (;ptr < end_ptr; ++ptr) {
			if (*ptr != ' ')
				break;
		}
		if (ptr >= end_ptr)
			return send_error(HTTP_ERROR_400, -1);
		cl = strtoul(ptr, NULL, 10);
	}

	bool expecting = 0;

	// Have the most likely request type first to skip needless
	// compares
	if (strncmp(req_buf, "GET", 3) == 0) {
		action = &lonely_http::GET;
		cur_request = HTTP_REQUEST_GET;
		ptr = req_buf + 3;

	// For POST requests, we also require a Content-Length that matches.
	} else if (strncmp(req_buf, "POST", 4) == 0) {
		if (cl == 0 || cl >= sizeof(body))
			return send_error(HTTP_ERROR_414, -1);
		// The body should be right here, we dont mind if stupid senders
		// send them separately
		if ((size_t)peer->recv(body, sizeof(body)) != cl)
			return send_error(HTTP_ERROR_400, -1);
		action = &lonely_http::POST;
		cur_request = HTTP_REQUEST_POST;
		ptr = req_buf + 4;
	} else if (strncmp(req_buf, "OPTIONS", 7) == 0) {
		action = &lonely_http::OPTIONS;
		cur_request = HTTP_REQUEST_OPTIONS;
		ptr = req_buf + 7;
	} else if (strncmp(req_buf, "HEAD", 4) == 0) {
		action = &lonely_http::HEAD;
		cur_request = HTTP_REQUEST_HEAD;
		ptr = req_buf + 4;
	} else if (strncmp(req_buf, "PUT", 3) == 0) {
		peer->blen = cl;
		if (strcasestr(req_buf, "\r\nExpect:"))
			expecting = 1;
		action = &lonely_http::PUT;
		cur_request = HTTP_REQUEST_PUT;
		ptr = req_buf + 3;
	} else if (strncmp(req_buf, "DELETE", 6) == 0) {
		action = &lonely_http::DELETE;
		cur_request = HTTP_REQUEST_DELETE;
		ptr = req_buf + 6;
	} else if (strncmp(req_buf, "TRACE", 5) == 0) {
		action = &lonely_http::TRACE;
		cur_request = HTTP_REQUEST_TRACE;
		ptr = req_buf + 5;
	} else if (strncmp(req_buf, "CONNECT", 7) == 0) {
		action = &lonely_http::CONNECT;
		cur_request = HTTP_REQUEST_CONNECT;
		ptr = req_buf + 7;
	} else {
		return send_error(HTTP_ERROR_400, 0);
	}

	for (; ptr < end_ptr; ++ptr) {
		if (*ptr != ' ')
			break;
	}

	if (ptr >= end_ptr)
		return send_error(HTTP_ERROR_400, -1);

	end_ptr = ptr + strcspn(ptr + 1, "? \t\r");

	if (end_ptr >= last_byte)
		return send_error(HTTP_ERROR_400, -1);
	end_ptr[1] = 0;

	// remove trailing / if not just a single slash, to avoid
	// indexgen lookups of /gif vs. /gif/ etc.
	if (end_ptr - ptr > 1 && *end_ptr == '/')
		*end_ptr = 0;

	if (cur_request == HTTP_REQUEST_PUT) {
		if (httpd_config::upload.size() == 0)
			return send_error(HTTP_ERROR_400, 0);

		if (expecting)
			peer->send("HTTP/1.1 100 Continue\r\n\r\n", 25);

		peer->path = httpd_config::upload;
		if (*ptr != '/')
			peer->path += "/";
		peer->path += ptr;
	} else
		peer->path = ptr;

	ptr = end_ptr + 2; // rest of header
	if (ptr > last_byte)
		return send_error(HTTP_ERROR_400, -1);

	if ((ptr2 = strcasestr(ptr, "Connection:")) && peer_idx < 30000) {
		ptr2 += 11;
		for (;ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}
		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400, -1);

		if (strncasecmp(ptr2, "keep-alive", 10) == 0)
			peer->keep_alive = 1;
		else
			peer->keep_alive = 0;
	} else
			peer->keep_alive = 0;

	if (vhosts && (ptr2 = strcasestr(ptr, "Host:"))) {
		ptr2 += 5;
		for (; ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}

		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400, -1);

		if ((end_ptr = strstr(ptr2, "\r\n"))) {

			*end_ptr = 0;

			// makes no sense
			if (string(ptr2) == "icons" || strstr(ptr2, ".."))
				return send_error(HTTP_ERROR_404, 0);

			// If already requesting vhost files (genindex), then, do not prepend
			// vhost path again
			if (!strstr(peer->path.c_str(), "vhost")) {
				string tmps = peer->path;
				peer->path = "/vhost";
				peer->path += ptr2;
				if (tmps != "/")
					peer->path += tmps;
			}
		} else {
			return send_error(HTTP_ERROR_400, -1);
		}
	}

	// Range: bytes 0-7350
	if ((ptr2 = strcasestr(ptr, "Range:")) != NULL) {
		if (cur_request != HTTP_REQUEST_GET)
			return send_error(HTTP_ERROR_416, -1);

		ptr2 += 6;
		for (; ptr2 < last_byte; ++ptr2) {
			if (*ptr2 != ' ')
				break;
		}
		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400, -1);
		if (strncmp(ptr2, "bytes=", 6) != 0)
			return send_error(HTTP_ERROR_416, -1);
		ptr2 += 6;
		if (ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400, -1);
		end_ptr = NULL;
		cur_start_range = strtoul(ptr2, &end_ptr, 10);
		if (!end_ptr || end_ptr == ptr2 || end_ptr + 1 >= last_byte)
			return send_error(HTTP_ERROR_400, -1);
		char *end_ptr2 = NULL;
		cur_end_range = strtoul(end_ptr + 1, &end_ptr2, 10);
		if (!end_ptr2 || end_ptr2 >= last_byte)
			return send_error(HTTP_ERROR_400, -1);
		// dont accept further ranges, one is enough
		if (*end_ptr2 != '\r')
			return send_error(HTTP_ERROR_416, -1);

		// Range: is from first byte to last byte _inclusive_; will be subtracted
		// in header reply later then
		if (cur_end_range)
			++cur_end_range;
		cur_range_requested = 1;
	}

	return (this->*action)();
}

// instantiate a lonely_http with http_state
template class lonely<http_client>;
template class lonely<rproxy_client>;



