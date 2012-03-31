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
#include <utility>
#include "log.h"


typedef enum {
	STATE_CONNECTING = 0,
	STATE_ACCEPTING,
	STATE_DECIDING,
	STATE_CONNECTED,
	STATE_TRANSFERING,
	STATE_CLOSING,
	STATE_NONE,
	STATE_ERROR
} status_t;


// basic state struct needed for an httpd server
struct http_state {
	int fd;
	status_t state;
	time_t alive_time, header_time;
	bool keep_alive;
	off_t offset;
	size_t copied, left;
	dev_t dev;
	ino_t ino;
	std::string path, from_ip;
	int ct;
	bool is_dev;
	size_t blen;

	http_state()
	 : fd(-1), state(STATE_ERROR), alive_time(0), header_time(0),
	   keep_alive(0), offset(0), copied(0), left(0), dev(0), ino(0), path(""), from_ip(""), ct(0),
	   is_dev(0), blen(0) {};

	// might be called twice, so no double-free's
	void cleanup()
	{
		fd = -1;
		copied = left = 0;
		offset = 0;
		keep_alive = 0;
		alive_time = header_time = 0;
		dev = ino = 0;
		ct = 0;
		is_dev = 0;
		state = STATE_NONE;
		path.clear(); from_ip.clear();
		blen = 0;
	}
};


template<typename state_engine>
class lonely {
protected:
	struct pollfd *pfds;
	int first_fd, max_fd;
	int cur_peer;
	int af;
	log_provider *logger;

	std::map<int, time_t> shutdown_fds;

	time_t cur_time;
	char gmt_date[64], local_date[64];

	std::string err;
	state_engine **fd2state;
	bool heavy_load;


	void cleanup(int);

	void shutdown(int);

	void calc_max_fd();

public:
	lonely()
	 : first_fd(0), max_fd(0), cur_peer(-1), logger(NULL), cur_time(0), err(""), fd2state(NULL), heavy_load(0) {};

	virtual ~lonely() { delete [] pfds; delete logger; };

	int init(const std::string &, const std::string &, int a = AF_INET);

	int open_log(const std::string &, const std::string &, int core);

	void log(const std::string &);

	virtual int loop() = 0;

	const char *why();
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


enum {
	TIMEOUT_ALIVE = 30,
	TIMEOUT_CLOSING = 5,
	TIMEOUT_HEADER = 3
};


struct inode {
	dev_t dev;
	ino_t ino;
};


extern std::string http_error_msgs[];


class lonely_http : public lonely<http_state> {
private:
	struct stat cur_stat;
	off_t cur_start_range;
	size_t cur_end_range;
	bool cur_range_requested;
	http_request_t cur_request;
	char hbuf[1024];		// header construction scratch store

	size_t mss;

	std::map<inode, int> file_cache;

	// pathname to (stat, content-type)
	std::map<std::string, std::pair<struct stat, int> > stat_cache;

	static const std::string hdr_format;

	int OPTIONS();

	int GET();

	int GETPOST();

	int HEAD();

	int POST();

	int PUT();

	int DELETE();

	int TRACE();

	int CONNECT();

	int de_escape_path();

	int send_http_header();

	int send_error(http_error_code_t);

	int stat();

	int open();

	int handle_request();

	int transfer();

public:
	bool vhosts;

	lonely_http(size_t s = 1024)
	        : cur_start_range(0), cur_end_range(0),
		  cur_range_requested(0), cur_request(HTTP_REQUEST_NONE),
	          mss(s), vhosts(0)
	{
		if (mss > 0x10000)
			mss = 0x10000;
	}

	virtual ~lonely_http() {}

	int send_genindex();

	void clear_cache();

	int loop();
};


#endif

