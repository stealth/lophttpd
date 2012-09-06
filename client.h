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

// All the client state machine declarations

#ifndef __client_h__
#define __client_h__

#include <string>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include "config.h"


typedef enum {
	STATE_CONNECTING = 0,
	STATE_ACCEPTING,
	STATE_DECIDING,
	STATE_CONNECTED,
	STATE_DOWNLOADING,
	STATE_UPLOADING,
	STATE_CLOSING,
	STATE_NONE,
	STATE_ERROR
} status_t;


typedef enum {
	FILE_REGULAR = 0,
	FILE_SPECIAL = 1,
	FILE_DEVICE = 2,
	FILE_PROC = 3
} file_t;


class http_client {
private:
	status_t d_state;
public:
	int file_fd, peer_fd;
	time_t alive_time, header_time;
	bool keep_alive;
	off_t offset;
	size_t copied, left;
	dev_t dev;
	ino_t ino;
	std::string path, from_ip;
	int ct, in_queue;
	file_t ftype;
	size_t blen;

	http_client()
	 : d_state(STATE_ERROR), file_fd(-1), peer_fd(-1), alive_time(0), header_time(0),
	   keep_alive(0), offset(0), copied(0), left(0), dev(0), ino(0), path(""), from_ip(""),
	   ct(0), in_queue(0), ftype(FILE_REGULAR), blen(0) {};

	~http_client() {};

	void cleanup();

	int sendfile(size_t);

	int send(const char *, size_t);

	int recv(void *, size_t);

	int peek(void *, size_t);

	status_t state() const { return d_state; };

	void transition(status_t s) { d_state = s; };
};


// distinguish between client and server side to find out
// about new requests on a keep-alive connection
typedef enum {
	HTTP_NONE = 0,
	HTTP_CLIENT,
	HTTP_SERVER
} http_instance_t;


class rproxy_client {
private:
	status_t d_state;
public:
	int fd, peer_fd, keep_alive;
	time_t alive_time, header_time;
	off_t offset;
	struct rproxy_config::backend node;
	std::string opath, from_ip;
	char buf[4096];
	size_t blen;
	uint64_t chunk_len;
	bool header, chunked;

	http_instance_t type;

	rproxy_client()
	 : d_state(STATE_ERROR), fd(-1), peer_fd(-1), keep_alive(0), alive_time(0), header_time(0),
	   opath(""), from_ip(""), blen(0),
	   chunk_len(0), header(1), chunked(0), type(HTTP_NONE) {};

	~rproxy_client() {};

	void cleanup();

	status_t state() const { return d_state; };

	void transition(status_t s) { d_state = s; };
};


#endif

