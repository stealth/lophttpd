/*
 * Copyright (C) 2008-2010 Sebastian Krahmer.
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

#ifndef __lonely_h__
#define __lonely_h__

#include <stdio.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <string>
#include <stdint.h>
#include <map>
#include "log.h"


class lonely {
private:
	struct pollfd *pfds;
	int first_fd, max_fd;

protected:
	int cur_peer;
	time_t cur_time;

	char gmt_date[64], local_date[64];

	std::string err;

	std::map<int, struct status *> fd2state;

	static const uint8_t timeout_alive, timeout_closing;

	void cleanup(int);

	void shutdown(int);

	void calc_max_fd();

	virtual int handle_request() = 0;

	virtual void clear_cache() = 0;

public:
	lonely() : cur_time(0) {};

	virtual ~lonely() { delete [] pfds; };

	int init(u_int16_t);

	int loop();

	virtual int transfer() = 0;

	const char *why();
};


struct peer_file {
	off_t offset;		// file offset
	size_t left, copied;	// how much to copy and copied
	int fd;			// fd to file to send
	std::string path;
};

typedef enum {
	HTTP_ERROR_400 = 0,
	HTTP_ERROR_401,
	HTTP_ERROR_404,
	HTTP_ERROR_405,
	HTTP_ERROR_406,
	HTTP_ERROR_411,
	HTTP_ERROR_414,
	HTTP_ERROR_416,
	HTTP_ERROR_500,
	HTTP_ERROR_501,
	HTTP_ERROR_503,
	HTTP_ERROR_END
} http_error_code_t;


typedef enum {
	HTTP_REQUEST_NONE = 0,
	HTTP_REQUEST_OPTIONS = 1,
	HTTP_REQUEST_GET,
	HTTP_REQUEST_HEAD,
	HTTP_REQUEST_POST,
	HTTP_REQUEST_PUT,
	HTTP_REQUEST_DELETE,
	HTTP_REQUEST_TRACE,
	HTTP_REQUEST_CONNECT
} http_request_t;


class lonely_http : public lonely {
private:
	struct stat cur_stat;
	std::string cur_path;
	off_t cur_start_range;
	size_t cur_end_range;
	bool cur_range_requested;
	http_request_t cur_request;
	std::map<int, struct peer_file> peer2file;
	log_provider *logger;

	static const uint8_t timeout_header;

	// stat(2) cache
	std::map<const std::string, struct stat> file2stat; 

	// open FD cache
	std::map<const std::string, int> file2fd;

	int OPTIONS();

	int GET();

	int HEAD();

	int POST();

	int PUT();

	int DELETE();

	int TRACE();

	int CONNECT();

	int de_escape_path();

	int send_http_header();

	int send_error(http_error_code_t);

	void log(const std::string &);

	int stat(const std::string &);

	int open(const std::string &);

public:
	bool vhosts;

	lonely_http()
	        : cur_path(""), cur_start_range(0), cur_end_range(0),
		  cur_range_requested(0), cur_request(HTTP_REQUEST_NONE),
	          logger(NULL), vhosts(0) {};

	virtual ~lonely_http() { delete logger;};

	int handle_request();

	virtual int transfer();

	int send_genindex();

	int open_log(const std::string &, const std::string &, int core);

	void clear_cache();
};


typedef enum {
	STATE_CONNECTING = 0,
	STATE_ACCEPTING,
	STATE_CONNECTED,
	STATE_TRANSFERING,
	STATE_CLOSING
} status_t;

struct status {
	int peer_fd;
	status_t state;
	time_t alive_time, header_time;
	bool keep_alive;
	struct sockaddr_in sin;
};


#endif

