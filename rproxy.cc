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
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include "socket.h"
#include "lonely.h"
#include "config.h"
#include "rproxy.h"
#include "client.h"
#include "flavor.h"


using namespace rproxy_config;
using namespace ns_socket;
using namespace std;


int rproxy::loop()
{
	int i = 0, wn = 0, afd = -1, peer_fd = -1;
	char from[64];
	ssize_t r = 0;
	size_t n = 0;
	struct tm tm;
	struct timeval tv;
	sockaddr_in sin;
	socklen_t slen = sizeof(sin);


	for (;;) {
		if (poll(pfds, max_fd + 1, 1000) < 0)
			continue;

		memset(&tv, 0, sizeof(tv));
		memset(&tm, 0, sizeof(tm));
		gettimeofday(&tv, NULL);

		// optimization: only stringify time if at least 1s elapsed
		if (cur_time != tv.tv_sec) {
			cur_time = tv.tv_sec;
			localtime_r(&cur_time, &tm);
			strftime(local_date, sizeof(local_date), "%a, %d %b %Y %H:%M:%S GMT%z", &tm);
			gmtime_r(&cur_time, &tm);
			strftime(gmt_date, sizeof(gmt_date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
		}

		// assert: pfds[i].fd == i
		for (i = first_fd; i <= max_fd; ++i) {

			if (fd2peer[i] && fd2peer[i]->state == STATE_CLOSING) {
				if (heavy_load || cur_time - fd2peer[i]->alive_time > TIMEOUT_CLOSING) {
					cleanup(i);
					continue;
				}
			}

			if (pfds[i].fd == -1)
				continue;

			if (!fd2peer[i])
				continue;

			// timeout hanging connections (with pending data) but not accepting
			// socket
			if (cur_time - fd2peer[i]->alive_time >= TIMEOUT_ALIVE &&
			    fd2peer[i]->state != STATE_ACCEPTING &&
			    (fd2peer[i]->blen > 0 || fd2peer[i]->state == STATE_DECIDING)) {

				// always call fd and its peer in pairs: cleanup() + cleanup() or
				// shutdown() + cleanup(). Otherwise re-used fd's can make troubles.
				cleanup(fd2peer[i]->peer_fd);
				cleanup(i);
				continue;
			}

			if ((pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
				if (fd2peer[i]->blen > 0) {
					writen(fd2peer[i]->peer_fd, fd2peer[i]->buf, fd2peer[i]->blen);
					fd2peer[i]->blen = 0;
				}
				shutdown(fd2peer[i]->peer_fd);
				cleanup(i);
				continue;
			}

			if (pfds[i].revents == 0)
				continue;

			peer_idx = i;
			peer = fd2peer[i];

			// new connection ready to accept?
			if (fd2peer[i]->state == STATE_ACCEPTING) {
				pfds[i].revents = 0;
				for (;;) {
					heavy_load = 0;
					afd = flavor::accept(i, (struct sockaddr *)&sin, &slen, flavor::NONBLOCK);
					if (afd < 0) {
						if (errno == EMFILE || errno == ENFILE)
							heavy_load = 1;
						break;
					}
					nodelay(afd);
					pfds[afd].fd = afd;
					pfds[afd].events = POLLIN;
					pfds[afd].revents = 0;

					if (!fd2peer[afd]) {
						fd2peer[afd] = new (nothrow) rproxy_client;

						if (!fd2peer[afd]) {
							err = "OOM";
							close(afd);
							return -1;
						}
					}

					if (inet_ntop(af, &sin.sin_addr, from, sizeof(from)) < 0)
						continue;

					fd2peer[afd]->from_ip = from;
					fd2peer[afd]->fd = afd;
					fd2peer[afd]->state = STATE_DECIDING;
					fd2peer[afd]->alive_time = cur_time;

					pfds[i].events = POLLOUT|POLLIN;

					if (afd > max_fd)
						max_fd = afd;
				}
				continue;
			} else if (fd2peer[i]->state == STATE_DECIDING) {
					// Also in DECIDING state, there might be response from server
					// to be sent to client
					if (pfds[i].revents & POLLOUT) {
						// actually data to send?
						if ((n = fd2peer[fd2peer[i]->peer_fd]->blen) > 0) {
							wn = writen(i, fd2peer[fd2peer[i]->peer_fd]->buf, n);
							if (wn <= 0) {
								shutdown(fd2peer[i]->peer_fd);
								cleanup(i);
								continue;
							}
							// non blocking write couldnt write it all at once
							if (wn != (int)n) {
								memmove(fd2peer[fd2peer[i]->peer_fd]->buf,
								        fd2peer[fd2peer[i]->peer_fd]->buf + wn,
								         n - wn);
								pfds[i].events = POLLOUT|POLLIN;
							} else {
								pfds[i].events = POLLIN;
							}
							fd2peer[fd2peer[i]->peer_fd]->blen -= wn;
						} else
							pfds[i].events &= ~POLLOUT;
						pfds[i].revents = 0;
						continue;
					}

					pfds[i].revents = 0;

					// else, there is POLLIN

					peer_fd = mangle_request_header();

					if (peer_fd == 0) {
						pfds[i].events = POLLIN;
						continue;
					} else if (peer_fd < 0) {
						cleanup(fd2peer[i]->peer_fd);
						cleanup(i);
						continue;
					}

					bool same_conn = (fd2peer[i]->peer_fd == peer_fd);
					// mangle_request_header() may return the same, already
					// esablished, connection if the same URL is requested again
					if (!same_conn) {
						// exception with the cleanup()+cleanup() pair calling,
						// however this one is OK, as the peer_fd is resetted by hand
						cleanup(fd2peer[i]->peer_fd);
						fd2peer[i]->peer_fd = peer_fd;
					}

					fd2peer[i]->state = STATE_CONNECTED;
					fd2peer[i]->alive_time = cur_time;
					fd2peer[i]->type = HTTP_CLIENT;
					fd2peer[i]->header = 0;

					if (!fd2peer[peer_fd]) {
						fd2peer[peer_fd] = new (nothrow) rproxy_client;
						if (!fd2peer[peer_fd]) {
							err = "OOM";
							cleanup(i);
							close(peer_fd);
							return -1;
						}
					}

					// only for new connections:
					if (!same_conn) {
						fd2peer[peer_fd]->fd = peer_fd;
						fd2peer[peer_fd]->peer_fd = i;
						fd2peer[peer_fd]->state = STATE_CONNECTING;
						fd2peer[peer_fd]->type = HTTP_SERVER;
					}

					fd2peer[peer_fd]->alive_time = cur_time;

					pfds[peer_fd].fd = peer_fd;
					pfds[peer_fd].events = POLLIN|POLLOUT;
					pfds[peer_fd].revents = 0;

					// only POLLIN, since we just fetched request and need
					// to forward it first
					pfds[i].events = POLLIN;
					if (fd2peer[peer_fd]->blen > 0)
						pfds[i].events |= POLLOUT;

					if (peer_fd > max_fd)
						max_fd = peer_fd;
			} else if (fd2peer[i]->state == STATE_CONNECTING) {
				if (finish_connecting(i) < 0) {
					err = "rproxy::loop::";
					err += ns_socket::why();
					cleanup(fd2peer[i]->peer_fd);
					cleanup(i);
					// log
					continue;
				}
				fd2peer[i]->state = STATE_CONNECTED;
				fd2peer[i]->alive_time = cur_time;

				// POLLOUT too, since mangle_request_header() already slurped data
				// from client
				pfds[i].events = POLLIN|POLLOUT;
				pfds[i].revents = 0;
			} else if (fd2peer[i]->state == STATE_CONNECTED) {

				// peer not ready yet
				if (!fd2peer[fd2peer[i]->peer_fd] ||
				    fd2peer[fd2peer[i]->peer_fd]->state == STATE_CONNECTING) {
					pfds[i].revents = 0;
					continue;
				}

				if (pfds[i].revents & POLLOUT) {
					// actually data to send?
					if ((n = fd2peer[fd2peer[i]->peer_fd]->blen) > 0) {
						wn = writen(i, fd2peer[fd2peer[i]->peer_fd]->buf, n);
						if (wn <= 0) {
							shutdown(fd2peer[i]->peer_fd);
							cleanup(i);
							continue;
						}
						// non blocking write couldnt write it all at once
						if (wn != (int)n) {
							memmove(fd2peer[fd2peer[i]->peer_fd]->buf,
							        fd2peer[fd2peer[i]->peer_fd]->buf + wn,
							         n - wn);
							pfds[i].events = POLLOUT|POLLIN;
						} else {
							pfds[i].events = POLLIN;
						}
						fd2peer[fd2peer[i]->peer_fd]->blen -= wn;
					} else
						pfds[i].events &= ~POLLOUT;
				}

				if (pfds[i].revents & POLLIN) {
					// still data in buffer? dont read() new data
					if (fd2peer[i]->blen > 0) {
						pfds[i].events |= POLLIN;
						pfds[fd2peer[i]->peer_fd].events = POLLOUT|POLLIN;
						pfds[i].revents = 0;
						continue;
					}

					r = more_bytes();

					if (r < 0) {
						// no need to flush data here, as we won't be here
						// with fd2peer[i]->blen > 0
						shutdown(fd2peer[peer_idx]->peer_fd);
						cleanup(peer_idx);
						continue;

					// could not read complete header or so
					} else if (r == 0) {
						pfds[peer_idx].events |= POLLIN;
						pfds[peer_idx].revents = 0;
						continue;
					}

					// peer has data to write
					pfds[fd2peer[i]->peer_fd].events = POLLOUT|POLLIN;
					pfds[i].events |= POLLIN;
				}

				pfds[i].revents = 0;
				fd2peer[i]->alive_time = cur_time;
				fd2peer[fd2peer[i]->peer_fd]->alive_time = cur_time;
			}

		}
		calc_max_fd();
	}

	return 0;
}


ssize_t rproxy::more_client_bytes()
{
	ssize_t r = 0;
	size_t n = sizeof(fd2peer[peer_idx]->buf);

	// already slurped in whole request?
	if (fd2peer[peer_idx]->chunk_len == 0) {
		fd2peer[peer_idx]->header = 1;
		fd2peer[peer_idx]->state = STATE_DECIDING;
		fd2peer[peer_idx]->alive_time = cur_time;
		fd2peer[peer_idx]->header_time = 0;
		return 0;
	}

	if (fd2peer[peer_idx]->chunk_len < sizeof(fd2peer[peer_idx]->buf))
		n = fd2peer[peer_idx]->chunk_len;

	r = read(peer_idx, fd2peer[peer_idx]->buf, n);

	if (r <= 0)
		return -1;

	fd2peer[peer_idx]->blen = r;

	// ... to change state again after each request
	fd2peer[peer_idx]->chunk_len -= r;
	if (fd2peer[peer_idx]->chunk_len == 0) {
		fd2peer[peer_idx]->header = 1;
		fd2peer[peer_idx]->state = STATE_DECIDING;
		fd2peer[peer_idx]->header_time = 0;
	}

	return r;
}


ssize_t rproxy::more_bytes()
{
	if (fd2peer[peer_idx]->type == HTTP_CLIENT)
		return more_client_bytes();

	return more_server_bytes();
}


ssize_t rproxy::more_server_bytes()
{
	ssize_t r = 0;
	size_t n = sizeof(fd2peer[peer_idx]->buf);
	char buf[4096], *ptr = NULL;


	if (fd2peer[peer_idx]->header) {
		errno = 0;
		memset(buf, 0, sizeof(buf));
		if ((r = recv(peer_idx, buf, sizeof(buf) - 1, MSG_PEEK)) <= 0) {
			if (errno == EAGAIN)
				return 0;
			return -1;
		}

		// If first read, set initial timestamp for header TO
		if (fd2peer[peer_idx]->header_time == 0)
			fd2peer[peer_idx]->header_time = cur_time;

		if ((ptr = strstr(buf, "\r\n\r\n")) == NULL) {
			if (cur_time - fd2peer[peer_idx]->header_time > TIMEOUT_HEADER)
				return -1;
			return 0;
		}

		size_t hlen = ptr - buf + 4;

		if (hlen >= sizeof(fd2peer[peer_idx]->buf))
			return -1;

		if ((r = read(peer_idx, fd2peer[peer_idx]->buf, hlen)) != (ssize_t)hlen)
			return -1;

		fd2peer[peer_idx]->buf[hlen] = 0;
		fd2peer[peer_idx]->blen = hlen;
		fd2peer[peer_idx]->header = 0;

		if (mangle_server_reply() < 0)
			return -1;

	// read chunk size, if chunked encoding and complete chunk or header has been slurped
	} else if (fd2peer[peer_idx]->chunked && fd2peer[peer_idx]->chunk_len == 0) {
		errno = 0;
		memset(buf, 0, sizeof(buf));
		if ((r = recv(peer_idx, buf, sizeof(buf) - 1, MSG_PEEK)) <= 0)
			return -1;

		// that was the last chunk?
		if (strncmp(buf, "0\r\n\r\n", 5) == 0) {
			if ((r = read(peer_idx, fd2peer[peer_idx]->buf, 5)) != 5)
				return -1;
			fd2peer[peer_idx]->blen = 5;
			fd2peer[peer_idx]->header = 1;
			fd2peer[peer_idx]->header_time = 0;
		} else {
			if ((ptr = strstr(buf, "\r\n")) == NULL)
				return -1;
			fd2peer[peer_idx]->chunk_len = strtoul(buf, NULL, 16);

			if (fd2peer[peer_idx]->chunk_len > 0x100000000)
				return -1;

			// also need to read in that 'chunksize\r\n' and the \r\n after the chunk
			fd2peer[peer_idx]->chunk_len += (ptr - buf + 2) + 2;
			n = sizeof(fd2peer[peer_idx]->buf);

			if (fd2peer[peer_idx]->chunk_len < n)
				n = fd2peer[peer_idx]->chunk_len;

			if ((r = read(peer_idx, fd2peer[peer_idx]->buf, n)) <= 0)
				return -1;

			fd2peer[peer_idx]->blen = r;
			fd2peer[peer_idx]->chunk_len -= r;
		}
	} else {
		if (fd2peer[peer_idx]->chunk_len < n)
			n = fd2peer[peer_idx]->chunk_len;

		r = read(peer_idx, fd2peer[peer_idx]->buf, n);

		if (r <= 0)
			return -1;

		fd2peer[peer_idx]->blen = r;
		fd2peer[peer_idx]->chunk_len -= r;

		if (fd2peer[peer_idx]->chunk_len == 0 && !fd2peer[peer_idx]->chunked) {
			fd2peer[peer_idx]->header = 1;
			fd2peer[peer_idx]->header_time = 0;
		}
	}

	return r;
}


int rproxy::mangle_server_reply()
{
	if (fd2peer[peer_idx]->type != HTTP_SERVER)
		return 0;

	size_t blen = fd2peer[peer_idx]->blen;
	char *hdr_end = NULL, *location = NULL, *nl = NULL, *buf = fd2peer[peer_idx]->buf, *ptr = NULL;

	if ((hdr_end = strstr(buf, "\r\n\r\n")) == NULL)
		return 0;
	if ((size_t)(hdr_end - buf) >= blen)
		return 0;

	fd2peer[peer_idx]->chunk_len = 0x100000000;
	fd2peer[peer_idx]->chunked = 0;
	if ((ptr = strcasestr(buf, "\nContent-Length:"))) {
		ptr += 16;
		if (ptr >= hdr_end)
			return -1;
		fd2peer[peer_idx]->chunk_len = strtoul(ptr, NULL, 10);
		if (fd2peer[peer_idx]->chunk_len > 0x100000000) {
			send_error(HTTP_ERROR_414);
			return -1;
		}
	} else if ((ptr = strcasestr(buf, "\nTransfer-Encoding:"))) {
		ptr += 19;
		if (ptr >= hdr_end)
			return -1;
		if (strcasestr(ptr, "chunked")) {
			fd2peer[peer_idx]->chunked = 1;

			// will be assigned in more_server_bytes()
			fd2peer[peer_idx]->chunk_len = 0;
		}
	}

	if ((location = strcasestr(buf, "\nLocation:")) == NULL)
		return 0;
	if (strstr(buf, "Redirect") == NULL)
		return 0;

	location += 10;
	while (*location == ' ' && location < hdr_end)
		++location;
	if ((size_t)(location - buf) >= blen)
		return -1;
	if ((nl = strchr(location, '\r')) == NULL)
		return -1;

	if ((size_t)(nl - buf) >= blen)
		return -1;

	map<string, string>::iterator i = location_map.begin();
	for (; i != location_map.end(); ++i) {
		if (strncmp(i->first.c_str(), location, i->first.size()) == 0)
			break;
	}

	if (i == location_map.end())
		return -1;

	string hdr = string(buf, blen);
	string new_loc = rproxy_config::location;
	new_loc += i->second;
	new_loc += "/";

	hdr.replace(location - buf, i->first.size(), new_loc);

	if (hdr.size() >= sizeof(fd2peer[peer_idx]->buf))
		return -1;
	memcpy(buf, hdr.c_str(), hdr.size());
	fd2peer[peer_idx]->blen = hdr.size();
	return 0;
}


// return -1 on error, 0 if no complete header yet,
// socket fd otherwise
int rproxy::mangle_request_header()
{
	char buf[4096], *ptr = NULL, *end_ptr = NULL, *path_begin = NULL,
	     *path_end = NULL, *host_begin = NULL, *host_end = NULL;
	int r = 0;


	memset(buf, 0, sizeof(buf));
	errno = 0;
	if ((r = recv(peer_idx, buf, sizeof(buf) - 1, MSG_PEEK)) <= 0) {
		if (errno == EAGAIN)
			return 0;
		return -1;
	}

	// If first read, set initial timestamp for header TO
	if (fd2peer[peer_idx]->header_time == 0)
		fd2peer[peer_idx]->header_time = cur_time;

	if ((ptr = strstr(buf, "\r\n\r\n")) == NULL) {
		if (cur_time - fd2peer[peer_idx]->header_time > TIMEOUT_HEADER) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		return 0;
	}

	size_t hlen = ptr - buf + 4;
	end_ptr = buf + hlen;

	if (read(peer_idx, buf, hlen) != (ssize_t)hlen) {
		send_error(HTTP_ERROR_500);
		return -1;
	}
	buf[hlen] = 0;

	if (strncmp(buf, "GET", 3) != 0 && strncmp(buf, "POST", 4) != 0 &&
	    strncmp(buf, "HEAD", 4) != 0 && strncmp(buf, "PUT", 3) != 0) {
		send_error(HTTP_ERROR_405);
		return -1;
	}

	ptr = buf;
	while (*ptr != ' ' && *ptr)
		++ptr;
	if (ptr >= end_ptr) {
		send_error(HTTP_ERROR_400);
		return -1;
	}
	while (*ptr == ' ')
		++ptr;
	if (ptr >= end_ptr || *ptr != '/') {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	const string &from_ip = fd2peer[peer_idx]->from_ip;

	path_begin = ptr;
	if ((path_end = strchr(ptr, '?')) == NULL) {
		if ((path_end = strchr(ptr, ' ')) == NULL) {
			if ((path_end = strchr(ptr, '\r')) == NULL) {
				send_error(HTTP_ERROR_400);
				return -1;
			}
		}
	}

	log(string(buf, path_end - buf));

	string path = string(path_begin, path_end - path_begin);
	if (path.size() < 1) {
		send_error(HTTP_ERROR_400);
		return -1;
	}

	fd2peer[peer_idx]->chunk_len = 0;
	if ((ptr = strcasestr(buf, "\nContent-Length:"))) {
		ptr += 16;
		if (ptr >= end_ptr) {
			send_error(HTTP_ERROR_400);
			return -1;
		}
		fd2peer[peer_idx]->chunk_len = strtoul(ptr, NULL, 10);
		if (fd2peer[peer_idx]->chunk_len > 0x100000000) {
			send_error(HTTP_ERROR_414);
			return -1;
		}
	} else if (strcasestr(buf, "\nTransfer-Encoding:")) {
		send_error(HTTP_ERROR_411);
		return -1;
	}

	// smash any existing X-Forward entries
	while ((ptr = strcasestr(buf, "\nX-Forwarded-For"))) {
		ptr[1] = 'Y';
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

	if (de_escape_path(path) < 0) {
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

	// No match? Do not kill connection, as some buggy browsers always
	// send a request for /favicon.ico, no matter what html-base is
	if (!mlen) {
		send_error(HTTP_ERROR_404, 0);
		return 0;
	}


	bool same_conn = 0;
	struct rproxy_config::backend b;

	// Is it the same path as in a possible earlier request?
	// Then we dont need to open a new connection
	if (match->first == fd2peer[peer_idx]->opath && fd2peer[peer_idx]->peer_fd > 0) {
		same_conn = 1;
		b = fd2peer[peer_idx]->node;
	} else {
		// Already decided about a node for this IP/path combination?
		map<pair<string, string>, struct backend>::iterator j =
			client_map.find(make_pair<string, string>(from_ip, match->first));

		if (j != client_map.end()) {
			b = j->second;
		} else {
			b = match->second.front();
			match->second.pop_front();
			match->second.push_back(b);
			client_map[make_pair<string, string>(from_ip, match->first)] = b;
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
		// replace \r\n\r\n by \r\nHost: ...\r\n\r\n
		new_hdr.replace(hlen - 2, 2, s);
	}

	if (path_end - path_begin > (int)mlen && b.path == "/")
		new_hdr.replace(path_begin - buf, mlen, "");
	else
		new_hdr.replace(path_begin - buf, mlen, b.path);


	string xfwd = "X-Forwarded-For: ";
	xfwd += from_ip;
	xfwd += "\r\n\r\n";
	new_hdr.replace(new_hdr.size() - 2, 2, xfwd);

	if (new_hdr.size() >= sizeof(fd2peer[peer_idx]->buf)) {
		send_error(HTTP_ERROR_414);
		return -1;
	}

	memcpy(fd2peer[peer_idx]->buf, new_hdr.c_str(), new_hdr.size());
	fd2peer[peer_idx]->blen = new_hdr.size();

	if (same_conn)
		return fd2peer[peer_idx]->peer_fd;

	fd2peer[peer_idx]->opath = match->first;
	fd2peer[peer_idx]->node = b;
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
		if (c == '\r' || c == 0 || c == '\n' || c == ' ')
			return -1;
		tmp.push_back(c);
		p.replace(pos, 3, tmp, 0, 1);
		tmp = "";
	}
	return 0;
}



int rproxy::send_error(http_error_code_t e, bool kill_conn)
{
	string http_header = "HTTP/1.1 ";

	if (e >= HTTP_ERROR_END)
		e = HTTP_ERROR_400;
	http_header += http_error_msgs[e];
	http_header += "\r\nServer: lophttpd\r\nDate: ";
	http_header += gmt_date;

	if (e == HTTP_ERROR_405)
		http_header += "\r\nAllow: GET, HEAD, POST, PUT";

	http_header += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

	if (writen(peer_idx, http_header.c_str(), http_header.size()) <= 0)
		return -1;

	if (kill_conn)
		shutdown(peer_idx);
	return 0;
}


