/*
 * Copyright (C) 2010-2012 Sebastian Krahmer.
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
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdlib.h>
#include "log.h"

using namespace std;


/*
static inline off_t next_aligned_size(off_t size)
{
	return (size + 1024*1024 + 0x1000)&~(0x1000-1);
}
*/

int log_provider::open_log(const string &logfile, const string &method, int core = 0)
{
	struct stat st;
	int flags = O_RDWR|O_CREAT;

	if (method != "mmap")
		flags |= O_APPEND;

	// safe default
	do_log = &log_provider::write_log;

	char lfile[1024];
	snprintf(lfile, sizeof(lfile), "%s.%d", logfile.c_str(), core);
	log_fd = open(lfile, flags, 0600);
	if (log_fd < 0) {
		err = "log_provider::open_log::open:";
		err += strerror(errno);
		return -1;
	}

	log_area = (void *)-1;
	log_index = 0;
	log_size = 1<<20;

	if (method == "mmap") {
		if (fstat(log_fd, &st) < 0) {
			err = "log_provider::open_log::fstat:";
			err += strerror(errno);
			return -1;
		}
		if (ftruncate(log_fd, st.st_size + log_size) < 0) {
			err = "log_provider::open_log::ftruncate:";
			err += strerror(errno);
			return -1;
		}
		if ((log_area = mmap(NULL, log_size, PROT_READ|PROT_WRITE, MAP_SHARED,
			log_fd, st.st_size)) == (void *)-1) {
			err = "log_provider::open_log::mmap:";
			err += strerror(errno);
			return -1;
		}
		do_log = &log_provider::mmap_log;
	}

	return 0;
}


int log_provider::log(const string &msg)
{
	return (this->*do_log)(msg);
}


int log_provider::write_log(const string &msg)
{
	ssize_t r = write(log_fd, msg.c_str(), msg.size());
	return (int)r;
}


int log_provider::mmap_log(const string &msg)
{
	if (log_area == (void *)-1)
		return -1;

	if (log_index + (off_t)msg.size() >= log_size) {
		struct stat st;
		if (munmap(log_area, log_size) < 0) {
			err = "log_provider::mmap_log::munmap:";
			err += strerror(errno);
			return -1;
		}
		if (fstat(log_fd, &st) < 0) {
			err = "log_provider::mmap_log::fstat:";
			err += strerror(errno);
			return -1;
		}
		if (ftruncate(log_fd, st.st_size + log_size) < 0) {
			err = "log_provider::mmap_log::ftruncate:";
			err += strerror(errno);
			return -1;
		}
		if ((log_area = mmap(NULL, log_size, PROT_READ|PROT_WRITE, MAP_SHARED,
			log_fd, st.st_size)) == (void *)-1) {
			err = "log_provider::mmap_log::mmap:";
			err += strerror(errno);
			return -1;
		}
		log_index = 0;
	}
	memcpy((char *)log_area + log_index, msg.c_str(), msg.size());
	log_index += msg.size();
	return 0;
}


#ifdef AIO_UNUSED
int log_provider::aio_log(const string &msg)
{
	int count = 0;
	bool error = 0;

	// finish last requests
	if (log_aio.aio_fildes == log_fd) {
		do {
			++count;
		} while (aio_error(&log_aio) == EINPROGRESS && count < 12);

		if (count == 12) {
			if (aio_cancel(log_fd, &log_aio) != AIO_CANCELED)
				error = 1;
		} else {
			if (aio_return(&log_aio) <= 0)
				error = 1;
		}
	}

	// free(NULL) is defined
	free((void *)log_aio.aio_buf);
	memset(&log_aio, 0, sizeof(log_aio));

	if (error)
		return -1;

	log_aio.aio_fildes = log_fd;
	log_aio.aio_buf = strdup(msg.c_str());
	log_aio.aio_nbytes = msg.size();
	aio_write(&log_aio);
	return 0;
}
#endif


log_provider::~log_provider()
{
	close(log_fd);
}

