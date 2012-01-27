/*
 * Copyright (C) 2012 Sebastian Krahmer.
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

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <string>
#include <list>
#include <new>
#include <map>
#include <arpa/inet.h>
#include "socket.h"
#include "lonely.h"
#include "config.h"
#include "rproxy.h"


using namespace rproxy_config;
using namespace NS_Socket;
using namespace std;

const uint8_t rproxy::timeout_header = 5;


int rproxy::loop()
{
	int i = 0, wn = 0, r = 0, afd = -1, peer_fd = -1;
	char from[64];
	size_t n = 0;
	sockaddr_in sin;
	socklen_t slen = sizeof(sin);

	for (;;) {
		if (poll(pfds, max_fd + 1, 1000) < 0)
			continue;

		cur_time = time(NULL);

		// assert: pfds[i].fd == i
		for (i = first_fd; i <= max_fd; ++i) {
			if (pfds[i].fd == -1)
				continue;

			if (!fd2state[i])
				continue;

			// timeout hanging connections (with pending data) but not accepting socket
			if (cur_time - fd2state[i]->last_t >= 20 &&
			    fd2state[i]->state != STATE_ACCEPTING &&
			    fd2state[i]->blen > 0) {
				cleanup(fd2state[i]->peer_fd);
				cleanup(i);
				continue;
			}

			if ((pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
				cleanup(fd2state[i]->peer_fd);
				cleanup(i);
				continue;
			}

			if (pfds[i].revents == 0)
				continue;

			cur_peer = i;

			// new connection ready to accept?
			if (fd2state[i]->state == STATE_ACCEPTING) {
				pfds[i].revents = 0;
				for (;;) {
#ifdef LINUX26
					afd = accept4(i, (struct sockaddr *)&sin, &slen, SOCK_NONBLOCK);
#else
					afd = accept(i, (struct sockaddr *)&sin, &slen);
#endif
					if (afd < 0)
						break;
					nodelay(afd);
					pfds[afd].fd = afd;
					pfds[afd].events = POLLIN;
					pfds[afd].revents = 0;

#ifndef LINUX26
					if (fcntl(afd, F_SETFL, O_RDWR|O_NONBLOCK) < 0) {
						cleanup(afd);
						err = "rproxy::loop::fcntl:";
						err += strerror(errno);
						return -1;
					}
#endif

					if (!fd2state[afd]) {
						fd2state[afd] = new (nothrow) rproxy_state;

						if (!fd2state[afd]) {
							err = "OOM";
							close(afd);
							return -1;
						}
					}

					if (inet_ntop(af, &sin.sin_addr, from, sizeof(from)) < 0)
						continue;
 
					fd2state[afd]->from_ip = from;
					fd2state[afd]->fd = afd;
					fd2state[afd]->state = STATE_DECIDING;
					fd2state[afd]->last_t = cur_time;
					fd2state[afd]->sin = sin;

					pfds[i].events = POLLOUT|POLLIN;

					if (afd > max_fd)
						max_fd = afd;
				}
				continue;
			} else if (fd2state[i]->state == STATE_DECIDING) {
					// Also in DECIDING state, there might be response from server
					// to be sent to client
					if (pfds[i].revents & POLLOUT) {
						// actually data to send?
						if ((n = fd2state[fd2state[i]->peer_fd]->blen) > 0) {
							wn = writen(i, fd2state[fd2state[i]->peer_fd]->buf, n);
							if (wn == 0) {
								shutdown(fd2state[i]->peer_fd);
								shutdown(i);
								continue;
							} else if (wn < 0) {
								cleanup(fd2state[i]->peer_fd);
								cleanup(i);
								continue;
							}
							// non blocking write couldnt write it all at once
							if (wn != (int)n) {
								memmove(fd2state[fd2state[i]->peer_fd]->buf,
								        fd2state[fd2state[i]->peer_fd]->buf + wn,
								         n - wn);
								pfds[i].events = POLLOUT|POLLIN;
							} else {
								pfds[i].events = POLLIN;
							}
							fd2state[fd2state[i]->peer_fd]->blen -= wn;
						} else
							pfds[i].events &= ~POLLOUT;
						pfds[i].revents = 0;
						continue;
					}

					pfds[i].revents = 0;

					// else, there is POLLIN

					peer_fd = mangle_request_header(i);

					if (peer_fd == 0) {
						pfds[i].events = POLLIN;
						continue;
					} else if (peer_fd < 0) {
						cleanup(fd2state[i]->peer_fd);
						cleanup(i);
						continue;
					}

					bool same_conn = (fd2state[i]->peer_fd == peer_fd);
					// mangle_request_header() may return the same, already
					// esablished, connection if the same URL is requested again
					if (!same_conn) {
						cleanup(fd2state[i]->peer_fd);
						fd2state[i]->peer_fd = peer_fd;
					}

					fd2state[i]->state = STATE_CONNECTED;
					fd2state[i]->last_t = cur_time;
					fd2state[i]->type = HTTP_CLIENT;

					if (!fd2state[peer_fd]) {
						fd2state[peer_fd] = new (nothrow) rproxy_state;
						if (!fd2state[peer_fd]) {
							err = "OOM";
							cleanup(i);
							close(peer_fd);
							return -1;
						}
					}

					// only for new connections:
					if (!same_conn) {
						fd2state[peer_fd]->peer_fd = i;
						fd2state[peer_fd]->state = STATE_CONNECTING;
						fd2state[peer_fd]->type = HTTP_SERVER;
					}

					fd2state[peer_fd]->last_t = cur_time;

					pfds[peer_fd].fd = peer_fd;
					pfds[peer_fd].events = POLLIN|POLLOUT;
					pfds[peer_fd].revents = 0;

					pfds[i].events = POLLIN|POLLOUT;

					if (peer_fd > max_fd)
						max_fd = peer_fd;
			} else if (fd2state[i]->state == STATE_CONNECTING) {
				if (finish_connecting(i) < 0) {
					err = "rproxy::loop::";
					err += NS_Socket::why();
					cleanup(fd2state[i]->peer_fd);
					cleanup(i);
					// log
					continue;
				}
				fd2state[i]->state = STATE_CONNECTED;
				fd2state[i]->last_t = cur_time;
				pfds[i].fd = i;

				// POLLOUT too, since mangle_request_header() already slurped data
				// from client
				pfds[i].events = POLLIN|POLLOUT;
				pfds[i].revents = 0;
			} else if (fd2state[i]->state == STATE_CONNECTED) {
				// peer not ready yet
				if (!fd2state[fd2state[i]->peer_fd] ||
				    fd2state[fd2state[i]->peer_fd]->state == STATE_CONNECTING) {
					pfds[i].revents = 0;
					continue;
				}

				if (pfds[i].revents & POLLOUT) {
					// actually data to send?
					if ((n = fd2state[fd2state[i]->peer_fd]->blen) > 0) {
						wn = writen(i, fd2state[fd2state[i]->peer_fd]->buf, n);
						if (wn == 0) {
							shutdown(fd2state[i]->peer_fd);
							shutdown(i);
							continue;
						} else if (wn < 0) {
							cleanup(fd2state[i]->peer_fd);
							cleanup(i);
							continue;
						}
						// non blocking write couldnt write it all at once
						if (wn != (int)n) {
							memmove(fd2state[fd2state[i]->peer_fd]->buf,
							        fd2state[fd2state[i]->peer_fd]->buf + wn,
							         n - wn);
							pfds[i].events = POLLOUT|POLLIN;
						} else {
							pfds[i].events = POLLIN;
						}
						fd2state[fd2state[i]->peer_fd]->blen -= wn;
					} else
						pfds[i].events &= ~POLLOUT;
				}

				if (pfds[i].revents & POLLIN) {
					// still data in buffer? dont read() new data
					if (fd2state[i]->blen > 0) {
						pfds[i].events = POLLIN;
						pfds[fd2state[i]->peer_fd].events = POLLOUT|POLLIN;
						pfds[i].revents = 0;
						continue;
					}
					n = sizeof(fd2state[i]->buf);

					// For HTTP clients, only read one request at a time ...
					if (fd2state[i]->type == HTTP_CLIENT) {

						// already slurped in whole request?
						if (fd2state[i]->req_len == 0) {
							fd2state[i]->state = STATE_DECIDING;
							pfds[i].events = POLLIN;
							pfds[i].revents = 0;
							fd2state[i]->last_t = cur_time;
							fd2state[i]->header_time = 0;
							continue;
						}

						if (fd2state[i]->req_len < sizeof(fd2state[i]->buf))
							n = fd2state[i]->req_len;
					}
					r = read(i, fd2state[i]->buf, n);
					if (r == 0) {
						shutdown(fd2state[i]->peer_fd);
						shutdown(i);
						continue;
					} else if (r < 0) {
						cleanup(fd2state[i]->peer_fd);
						cleanup(i);
						continue;
					}

					// ... to change state again after each request
					if (fd2state[i]->type == HTTP_CLIENT) {
						fd2state[i]->req_len -= r;
						if (fd2state[i]->req_len == 0) {
							fd2state[i]->state = STATE_DECIDING;
							fd2state[i]->header_time = 0;
						}
					}

					fd2state[i]->blen = r;
					// peer has data to write
					pfds[fd2state[i]->peer_fd].events = POLLOUT|POLLIN;
					pfds[i].events = POLLIN;
				}

				pfds[i].revents= 0;
				fd2state[i]->last_t = cur_time;
				fd2state[fd2state[i]->peer_fd]->last_t = cur_time;
			} else if (fd2state[i]->state == STATE_CLOSING) {
				cleanup(i);
			}

		}
		calc_max_fd();
	}

	return 0;
}


// return -1 on error, 0 if no complete header yet,
// socket fd otherwise
int rproxy::mangle_request_header(int sock)
{
	char buf[2048], *ptr = NULL, *end_ptr = NULL, *path_begin = NULL,
	     *path_end = NULL, *host_begin = NULL, *host_end = NULL;
	int r = 0;

	memset(buf, 0, sizeof(buf));
	errno = 0;
	if ((r = recv(sock, buf, sizeof(buf) - 1, MSG_PEEK)) <= 0) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}

	// If first read, set initial timestamp for header TO
	if (fd2state[cur_peer]->header_time == 0)
		fd2state[cur_peer]->header_time = cur_time;

	if ((ptr = strstr(buf, "\r\n\r\n")) == NULL) {
		if (cur_time - fd2state[cur_peer]->header_time > timeout_header) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		return 0;
	}

	size_t hlen = ptr - buf + 4;
	end_ptr = buf + hlen;

	if (read(sock, buf, hlen) != (ssize_t)hlen) {
		send_error(HTTP_ERROR_500);
		return -1;
	}
	buf[hlen] = 0;

	if ((ptr = strstr(buf, "/")) == NULL) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	// Path must start inside the first line
	if (strchr(buf, '\n') <= ptr) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	path_begin = ptr;
	if ((path_end = strchr(ptr, '?')) == NULL) {
		if ((path_end = strchr(ptr, ' ')) == NULL) {
			if ((path_end = strchr(ptr, '\r')) == NULL) {
				send_error(HTTP_ERROR_400);
				return -1;
			}
		}
	}
	string path = string(path_begin, path_end - path_begin);
	if (path.size() < 1) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	fd2state[sock]->req_len = 0;
	if ((ptr = strcasestr(buf, "\nContent-Length:"))) {
		if (ptr + 21 >= end_ptr) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		fd2state[sock]->req_len = strtoul(ptr, NULL, 10);
		if (fd2state[sock]->req_len > 0x10000000) {
			send_error(HTTP_ERROR_414);
			return -1;
		}
	}
	if ((ptr = strcasestr(buf, "\nHost:"))) {
		ptr += 6;
		host_begin = ptr;
		if (ptr + 2 >= end_ptr) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		while (*ptr != '\r')
			++ptr;
		if (ptr >= end_ptr) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		host_end = ptr;
	}

	if (de_escape_path(path) < 0 || host_begin <= path_begin) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	// Find the longest match for the given path in our URL mapping
	map<string, list<struct rproxy_config::backend> >::iterator i = url_map.begin(), match = url_map.end();
	string::size_type mlen = 0;
	for (; i != url_map.end(); ++i) {
		if (strncmp(path.c_str(), i->first.c_str(), i->first.size()) == 0) {
			if (mlen < i->first.size()) {
				match = i;
				mlen = i->first.size();
			}
		}
	}

	// No match?
	if (!mlen) {
		send_error(HTTP_ERROR_404);
		return -1;
	}


	bool same_conn = 0;
	struct rproxy_config::backend b;

	// Is it the same path as in a possible earlier request?
	// Then we dont need to open a new connection
	if (match->first == fd2state[sock]->opath && fd2state[sock]->peer_fd > 0) {
		same_conn = 1;
		b = fd2state[sock]->node;
	} else {
		// Already decided about a proxy for this IP/path combination?
		map<pair<string, string>, struct backend>::iterator j =
			client_map.find(make_pair<string, string>(fd2state[sock]->from_ip, match->first));

		if (j != client_map.end()) {
			b = j->second;
		} else {
			b = match->second.front();
			match->second.pop_front();
			match->second.push_back(b);
		}
	}

	// build new header, replacing Path and Host
	// Replace Host: first, so the offsets dont become invalid,
	// since Host: is located after Path
	string new_hdr = buf;
	if (host_begin) {
		string s = b.host;
		if (b.port != 80) {
			char p[12];
			snprintf(p, sizeof(p), ":%hu", b.port);
			s += p;
		}
		new_hdr.replace(host_begin - buf, host_end - host_begin, s);
	} else {
		string s = "Host: ";
		s += b.host;
		if (b.port != 80) {
			char p[12];
			snprintf(p, sizeof(p), ":%hu", b.port);
			s += p;
		}
		s += "\r\n\r\n";
		// replace \r\n\r\n by Host: ...\r\n\r\n
		new_hdr.replace(hlen - 4, 4, s);
	}

	if (path_end - path_begin > (int)mlen && b.path == "/")
		new_hdr.replace(path_begin - buf, mlen, "");
	else
		new_hdr.replace(path_begin - buf, mlen, b.path);


	//XXX X-Forwarded-For

	if (new_hdr.size() >= sizeof(fd2state[sock]->buf)) {
		send_error(HTTP_ERROR_414);
		return -1;
	}

	memcpy(fd2state[sock]->buf, new_hdr.c_str(), new_hdr.size());
	fd2state[sock]->blen = new_hdr.size();

	if (same_conn)
		return fd2state[sock]->peer_fd;

	fd2state[sock]->opath = match->first;
	fd2state[sock]->node = b;
	return tcp_connect_nb(b.ai, 0);
}


int rproxy::de_escape_path(string &p)
{
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
		if (c == '\r' || c == 0 || c == '\n')
			return -1;
		tmp.push_back(c);
		p.replace(pos, 3, tmp, 0, 1);
		tmp = "";
	}
	return 0;
}



int rproxy::send_error(http_error_code_t e)
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

	if (writen(cur_peer, http_header.c_str(), http_header.size()) <= 0)
		return -1;

	shutdown(cur_peer);
	return 0;
}


