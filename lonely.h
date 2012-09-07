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
#include <unistd.h>
#include <map>
#include <utility>
#include "client.h"
#include "log.h"

#ifdef USE_SSL
extern "C" {
#include <openssl/ssl.h>
}
#endif


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



template<typename T>
class lonely {
protected:
	struct pollfd *pfds;
	int first_fd, max_fd;
	T *peer;
	T **fd2peer;
	int peer_idx;
	uint32_t n_clients;
	int af;
	log_provider *logger;

	time_t cur_time;
	suseconds_t cur_usec;
	char gmt_date[64], local_date[64];

	std::string err;

	bool heavy_load;
	size_t so_sndbuf;

	void cleanup(int);

	void shutdown(int);

	void calc_max_fd();

public:
	lonely()
	 : first_fd(0), max_fd(0), peer(NULL), fd2peer(NULL), peer_idx(-1), n_clients(0), logger(NULL),
	   cur_time(0), cur_usec(0), err(""), heavy_load(0), so_sndbuf(4096)
	{
	}

	virtual ~lonely() { delete [] pfds; delete logger; }

	int init(const std::string &, const std::string &, int a = AF_INET);

	int open_log(const std::string &, const std::string &, int core);

	void log(const std::string &);

	virtual int loop() = 0;

	const char *why();

};


enum {
	TIMEOUT_ALIVE = 30,
	TIMEOUT_CLOSING = 5,
	TIMEOUT_HEADER = 3
};


enum {
	MANY_RECEIVERS = 500,
	MIN_SEND_SIZE = 64,
	DEFAULT_SEND_SIZE = 1024,
	MAX_SEND_SIZE = 4096
};


struct inode {
	dev_t dev;
	ino_t ino;
};



class lonely_http : public lonely<http_client> {
private:
	struct stat cur_stat;
	off_t cur_start_range;
	size_t cur_end_range;
	bool cur_range_requested, forced_send_size;
	http_request_t cur_request;

	char hbuf[1024];		// header construction scratch store

	uint16_t min_send, n_send, max_send;

	std::map<inode, int> file_cache;

	// pathname to (stat, content-type)
	std::map<std::string, std::pair<struct stat, int> > stat_cache;

	static const std::string hdr_fmt, chunked_hdr_fmt, part_hdr_fmt, put_hdr_fmt;

#ifdef USE_SSL
	SSL_CTX *ssl_ctx;
	SSL_METHOD *ssl_method;
#endif

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

	int download();

	int upload();

public:
	bool vhosts;

	lonely_http(uint16_t s = DEFAULT_SEND_SIZE)
	        : cur_start_range(0), cur_end_range(0),
		  cur_range_requested(0), forced_send_size(0), cur_request(HTTP_REQUEST_NONE),
	          min_send(MIN_SEND_SIZE), n_send(s), max_send(MAX_SEND_SIZE),
	          vhosts(0)
	{
		if (n_send != DEFAULT_SEND_SIZE)
			forced_send_size = 1;
		if (n_send > max_send)
			n_send = max_send;
		if (n_send < min_send)
			n_send = min_send;
#ifdef USE_SSL
		ssl_ctx = NULL;
		ssl_method = NULL;
#endif
	}

	virtual ~lonely_http()
	{
#ifdef USE_SSL
		if (ssl_ctx)
			SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
#endif
	}

	int setup_ssl(const std::string &, const std::string &);

	int send_genindex();

	void clear_cache();

	int loop();
};


extern std::string http_error_msgs[];

#endif

