/*
 * Copyright (C) 2008-2012 Sebastian Krahmer.
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


#include <string>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "flavor.h"
#include "socket.h"
#include "client.h"

#ifdef USE_SSL
extern "C" {
#include <openssl/ssl.h>
}
#endif


using namespace std;
using namespace ns_socket;

const int http_client::TIMEOUT_SSL = 3;

// might be called twice, so no double-free's
void http_client::cleanup()
{
	if (d_state == STATE_UPLOADING)
		close(file_fd);
	file_fd = -1;
	peer_fd = -1;
	copied = left = 0;
	offset = 0;
	keep_alive = 0;
	alive_time = header_time = ssl_time = 0;
	dev = ino = 0;
	ct = in_queue = 0;
	ftype = FILE_REGULAR;
	d_state = STATE_NONE;
	path.clear(); from_ip.clear();
	blen = 0;
	ssl_enabled = 0;

#ifdef USE_SSL
	if (ssl)
		SSL_free(ssl);
	ssl = NULL;
#endif

}


ssize_t http_client::send(const char *buf, size_t n)
{

#ifdef USE_SSL
	int r = 0;
	if (ssl_enabled) {
		r = SSL_write(ssl, buf, n);
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			ssl_time = alive_time;
			break;
		default:
			r = -1;
		}

		return r;
	}
#endif

	return writen(peer_fd, buf, n);
}


ssize_t http_client::sendfile(size_t n)
{

#ifdef USE_SSL
	ssize_t r = 0, l = 0;
	char buf[n], siz[32];

	if (ssl_enabled) {
		if (alive_time - ssl_time > TIMEOUT_SSL)
			return -1;
		r = pread(file_fd, buf, n, offset);

		if (ftype == FILE_PROC) {
			if (r < 0) {
				if (errno == EAGAIN)
					errno = EBADF;
				return -1;
			} else if (r > 0) {
				l = snprintf(siz, sizeof(siz), "%x\r\n", (int)r);
				if (SSL_write(ssl, siz, l) != l)
					return -1;
				if (SSL_write(ssl, buf, r) != r)
					return -1;
				if (SSL_write(ssl, "\r\n", 2) != 2)
					return -1;
				offset += r;
				copied += r;
			} else {
				if (SSL_write(ssl, "0\r\n\r\n", 5) != 5)
					return -1;
				left = 0;
			}
			ssl_time = alive_time;
			return r;
		}

		if (r <= 0) {
			if (errno == EAGAIN)
				errno = EBADF;
			return -1;
		}

		r = SSL_write(ssl, buf, r);
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			ssl_time = alive_time;
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			r = 0;
			break;
		default:
			return -1;
		}

		offset += r;
		left -= r;
		copied += r;
		return r;
	}
#endif

	return flavor::sendfile(peer_fd, file_fd, &offset, // updated by sendfile
	                        n,
	                        left,	// updated by sendfile
	                        copied,	// updated by sendfile
	                        ftype);
}


ssize_t http_client::recv(void *buf, size_t n)
{

#ifdef USE_SSL
	int r = 0;
	if (ssl_enabled) {
		r = SSL_read(ssl, buf, n);
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			ssl_time = alive_time;
			break;
		default:
			r = -1;
		}

		return r;
	}
#endif

	return ::recv(peer_fd, buf, n, MSG_DONTWAIT);
}


ssize_t http_client::peek(void *buf, size_t n)
{

#ifdef USE_SSL
	int r = 0;
	if (ssl_enabled) {
		r = SSL_peek(ssl, buf, n);
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			ssl_time = alive_time;
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			if (alive_time - ssl_time > TIMEOUT_SSL)
				r = -1;
			else
				r = 0;
			break;
		default:
			r = -1;
		}

		return r;
	}
#endif

	return ::recv(peer_fd, buf, n, MSG_PEEK);
}


#ifdef USE_SSL
int http_client::ssl_accept(SSL_CTX *ssl_ctx)
{
	int r = 0;

	// may be re-entered of no complete handshake has been seen yet
	if (!ssl) {
		if ((ssl = SSL_new(ssl_ctx)) == NULL)
			return -1;
		SSL_set_fd(ssl, peer_fd);
		ssl_time = alive_time;
	}

	r = SSL_accept(ssl);

	switch (SSL_get_error(ssl, r)) {
	case SSL_ERROR_NONE:
		d_state = STATE_CONNECTED;
		ssl_enabled = 1;
		keep_alive = 1;
		ssl_time = alive_time;
		return 0;

	// no complete handshake yet? Try later
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		if (alive_time - ssl_time > TIMEOUT_SSL)
			return -1;
		return 0;
	default:
		return -1;
	}

	return 0;
}
#endif


void rproxy_client::cleanup()
{
	file_fd = fd = peer_fd = -1;
	d_state = STATE_NONE;
	type = HTTP_NONE;
	node.host.clear(); node.path.clear(); opath.clear(); from_ip.clear();
	blen = chunk_len = 0;
	header = 1;
	chunked = 0;
	alive_time = header_time = 0;
}

