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
#include <sys/types.h>
#include <sys/socket.h>
#include "flavor.h"
#include "socket.h"
#include "client.h"

using namespace std;
using namespace ns_socket;

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
	alive_time = header_time = 0;
	dev = ino = 0;
	ct = in_queue = 0;
	ftype = FILE_REGULAR;
	d_state = STATE_NONE;
	path.clear(); from_ip.clear();
	blen = 0;
}


int http_client::send(const char *buf, size_t n)
{
	return writen(peer_fd, buf, n);
}


int http_client::sendfile(size_t n)
{
	return flavor::sendfile(peer_fd, file_fd, &offset, // updated by sendfile
	                        n,
	                        left,	// updated by sendfile
	                        copied,	// updated by sendfile
	                        ftype);
}


int http_client::recv(void *buf, size_t n)
{
	return ::recv(peer_fd, buf, n, MSG_DONTWAIT);
}


int http_client::peek(void *buf, size_t n)
{
	return ::recv(peer_fd, buf, n, MSG_PEEK);
}


void rproxy_client::cleanup()
{
	fd = peer_fd = -1;
	d_state = STATE_NONE;
	type = HTTP_NONE;
	node.host.clear(); node.path.clear(); opath.clear(); from_ip.clear();
	blen = chunk_len = 0;
	header = 1;
	chunked = 0;
	alive_time = header_time = 0;
}

