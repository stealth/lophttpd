/*
 * Copyright (C) 2004-2012 Sebastian Krahmer.
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
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <cstring>
#include <string>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <cstdlib>
#include "socket.h"

namespace ns_socket {

using namespace std;

string error;

const char *why()
{
	return error.c_str();
}

// disable Mr. Nagle's algorithm
int nodelay(int sock)
{
	int one = 1;
	socklen_t len = sizeof(one);

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, len) < 0) {
		error = "ns_socket::nodelay::setsockopt: ";
		error += strerror(errno);
		return -1;
	}

	return 0;
}

// make socket ready for port-reuse
int reuse(int sock)
{
	int one = 1;
	socklen_t len = sizeof(one);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, len) < 0) {
		error = "ns_socket::reuse::setsockopt: ";
		error += strerror(errno);
		return -1;
	}

	return 0;
}


int bind_local(int sock, const struct sockaddr *s, socklen_t slen, bool do_listen)
{
	if (reuse(sock) < 0)
		return -1;

	if (bind(sock, s, slen) < 0) {
		error = "ns_socket::bind_local::bind: ";
		error += strerror(errno);
		return -1;
	}

	if (do_listen) {
		if (listen(sock, 100000) < 0) {
			if (listen(sock, 10000) < 0) {
				if (listen(sock, SOMAXCONN) < 0) {
					error = "ns_socket::bind_local::listen: ";
					error += strerror(errno);
					return -1;
				}
			}
		}
	}

	return 0;
}


int bind_local(int sock, uint16_t port, int af, bool do_listen, int tries)
{
	sockaddr_in sin4;
	sockaddr_in6 sin6;
	sockaddr *sin = (sockaddr *)&sin4;
	socklen_t slen = sizeof(sin4);

	if (af == AF_INET6) {
		sin = (sockaddr *)&sin6;
		slen = sizeof(sin6);
	}

	// XXX: static since connect will ne non-blocking, thus bind() will never fail
	static int i = 0;

	memset(&sin4, 0, sizeof(sin4));
	memset(&sin6, 0, sizeof(sin6));

	sin4.sin_family = sin6.sin6_family = af;

	if (reuse(sock) < 0)
		return -1;

	for (; i < tries; ++i) {
		sin4.sin_port = sin6.sin6_port = htons(port + i);
		if (bind(sock, sin, slen) < 0 && 
		    (errno != EADDRINUSE || i == tries - 1)) {
			error = "ns_socket::bind_local::bind: ";
			error += strerror(errno);
			return -1;
		} else {
			++i;
			break;
		}
	}

	if (do_listen) {
		if (listen(sock, SOMAXCONN) < 0) {
			error = "ns_socket::bind_local::listen: ";
			error += strerror(errno);
			return -1;
		}
	}
	return 0;
}


int tcp_connect_nb(const struct addrinfo &ai, uint16_t local_port)
{
	int sock = socket(ai.ai_family, ai.ai_socktype, 0);
	if (sock < 0) {
		error = "ns_socket::tcp_connect_nb::socket:";
		error += strerror(errno);
		return -1;
	}

	// not needed until FREEBIND
	//int one = 1;
	//setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one ,sizeof(one));
	if (local_port > 0) {
		if (bind_local(sock, local_port, ai.ai_family, 0, 1000) < 0)
			return -1;
	}

	if (fcntl(sock, F_SETFL, O_RDWR|O_NONBLOCK) < 0) {
		error = "ns_socket::tcp_connect_nb::fcntl:";
		error += strerror(errno);
		return -1;
	}

	if (connect(sock, ai.ai_addr, ai.ai_addrlen) < 0 &&
	    errno != EINPROGRESS) {
		error = "ns_socket::tcp_connect_nb::fcntl:";
		error += strerror(errno);
		return -1;
	}

	return sock;
}


int finish_connecting(int fd)
{
	int e = 0;
	socklen_t len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &len) < 0 || e < 0) {
		error = "ns_socket::finish_connecting::getsockopt:";
		error += strerror(errno);
		return -1;
	}
	return nodelay(fd);
}


int readn(int fd, void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = read(fd, ptr+o, len)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = write(fd, ptr+o, len)) <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return o;
			return n;
		}
		len -= n;
		o += n;
	}
	return o;
}

} // namespace

