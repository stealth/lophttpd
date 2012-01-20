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

namespace NS_Socket {

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
		error = "NS_Socket::nodelay::setsockopt: ";
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
		error = "NS_Socket::reuse::setsockopt: ";
		error += strerror(errno);
		return -1;
	}

	return 0;
}


int bind_local(int sock, const string &host, const string &port, bool do_listen, int af)
{
	struct addrinfo *ai = NULL, hints;
	int r;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo(host.c_str(), port.c_str(), &hints, &ai)) < 0) {
		error = "NS_Socket::bind_local::getaddrinfo:";
		error += gai_strerror(r);
		return -1;
	}

	if (reuse(sock) < 0)
		return -1;

	if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
		error = "NS_Socket::bind_local::bind: ";
		error += strerror(errno);
		return -1;
	}

	freeaddrinfo(ai);

	if (do_listen) {
		if (listen(sock, 10000) < 0) {
			if (listen(sock, SOMAXCONN) < 0) {
				error = "NS_Socket::bind_local::listen: ";
				error += strerror(errno);
				return -1;
			}
		}
	}

	return 0;
}


int bind_local(int sock, u_int16_t port, bool do_listen, int tries)
{
	struct sockaddr_in saddr;
	// XXX: static since connect will ne non-blocking, thus bind() will never fail
	static int i = 0;

	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_family = AF_INET;

	if (reuse(sock) < 0)
		return -1;

	for (; i < tries; ++i) {
		saddr.sin_port = htons(port + i);
		if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0 && 
		    (errno != EADDRINUSE || i == tries - 1)) {
			error = "NS_Socket::bind_local::bind: ";
			error += strerror(errno);
			return -1;
		} else {
			++i;
			break;
		}
	}

	if (do_listen) {
		if (listen(sock, SOMAXCONN) < 0) {
			error = "NS_Socket::bind_local::listen: ";
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
		error = "NS_Socket::tcp_connect_nb::socket:";
		error += strerror(errno);
		return -1;
	}

	if (local_port > 0) {
		if (bind_local(sock, local_port, 0, 1000) < 0)
			return -1;
	}

	int one = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one ,sizeof(one));

	int f;
	if ((f = fcntl(sock, F_GETFL, 0)) < 0) {
		error = "NS_Socket::tcp_connect_nb::fcntl:";
		error += strerror(errno);
		return -1;
	}
	if (fcntl(sock, F_SETFL, f|O_NONBLOCK) < 0) {
		error = "NS_Socket::tcp_connect_nb::fcntl:";
		error += strerror(errno);
		return -1;
	}

	if (connect(sock, ai.ai_addr, ai.ai_addrlen) < 0 &&
	    errno != EINPROGRESS) {
		error = "NS_Socket::tcp_connect_nb::fcntl:";
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
		error = "NS_Socket::finish_connecting::getsockopt:";
		error += strerror(errno);
		return -1;
	}
	int f = 0;
	f = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, f & ~O_NONBLOCK);

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
		if ((n = write(fd, ptr+o, len)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}
}; // namespace

