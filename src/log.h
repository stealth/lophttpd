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


#ifndef lophttpd_log_h
#define lophttpd_log_h

#include <string>
#include <sys/types.h>

#ifndef ANDROID
#include <aio.h>
#endif


class log_provider {
private:
	int log_fd;

// Need to disable -pedantic for stupid glinc header, having a 0-sized array for alignment inside a struct
// of aio!
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#ifndef ANDROID
	struct aiocb log_aio;
#endif
#pragma GCC diagnostic pop

	void *log_area;
	off_t log_index, log_size;

	int write_log(const std::string &);

	int mmap_log(const std::string &);

	int aio_log(const std::string &);

	int (log_provider::*do_log)(const std::string &);

	std::string err;

public:

	const char *why() { return err.c_str(); };

	int log(const std::string &);

	int open_log(const std::string &, const std::string &, int core);

	log_provider()
		: log_fd(-1), log_area((void *)-1), log_index(0), log_size(0)
	{
	};

	~log_provider();
};

#endif

