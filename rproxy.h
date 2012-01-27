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

#ifndef __rproxy_h__
#define __rproxy_h__

#include <stdio.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <string>
#include <stdint.h>
#include <map>
#include <utility>
#include "config.h"
#include "lonely.h"
#include "log.h"


// distinguish between client and server side to find out
// about new requests on a keep-alive connection
typedef enum {
	HTTP_NONE = 0,
	HTTP_CLIENT,
	HTTP_SERVER
} http_instance_t;


struct rproxy_state {
	int fd, peer_fd, keep_alive;
	status_t state;
	time_t last_t, header_time;
	off_t offset;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct rproxy_config::backend node;
	std::string opath, from_ip;
	char buf[4096];
	size_t blen, req_len;

	http_instance_t type;

	rproxy_state()
	 : fd(-1), peer_fd(-1), keep_alive(0), state(STATE_ERROR), last_t(0), header_time(0),
	   opath(""), from_ip(""), blen(0),
	   req_len(0), type(HTTP_NONE) {};

	void cleanup()
	{
		fd = peer_fd = -1;
		state = STATE_NONE;
		type = HTTP_NONE;
		node.host.clear(); node.path.clear(); opath.clear(); from_ip.clear();
		blen = req_len = 0;
		last_t = header_time = 0;
	}
};


class rproxy : public lonely<rproxy_state> {
private:
	std::map<std::pair<std::string, std::string>, struct rproxy_config::backend> client_map;

	int mangle_request_header(int);

	int send_error(http_error_code_t);

	int de_escape_path(std::string &);

	static const uint8_t timeout_header;

public:
	rproxy() {};

	virtual ~rproxy() { };

	virtual int loop();
};


#endif

