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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/disk.h>
#include <sys/ioctl.h>

#include "socket.h"
#include "flavor.h"
#include "lonely.h"


namespace flavor {

using namespace ns_socket;

int accept(int fd, struct sockaddr *saddr, socklen_t *slen, int flags)
{
	int afd = 0;

	if ((afd = accept(fd, saddr, slen)) < 0)
		return -1;
	if (flags == NONBLOCK) {
		// no error check
		fcntl(afd, F_SETFL, O_RDWR|O_NONBLOCK);
	}
	return afd;
}


bool servable_device(const struct stat &st)
{
	return S_ISCHR(st.st_mode);
}


bool servable_file(const struct stat &st)
{
	// no S_ISLNK() since stat() was used
	return S_ISCHR(st.st_mode) || S_ISREG(st.st_mode) || S_ISDIR(st.st_mode);
}


int device_size(const std::string &path, size_t &size)
{
	int fd = ::open(path.c_str(), O_RDONLY|O_NOCTTY);
	if (fd < 0)
		return -1;

	int r = 0, saved_errno = 0;
	if (ioctl(fd, DIOCGMEDIASIZE, &size) < 0) {
		r = -1;
		saved_errno = errno;
	}
	close(fd);
	errno = saved_errno;
	return r;
}


int in_send_queue(int peer)
{
	int n = 0;
	ioctl(peer, FIONWRITE, &n);
	return n;
}


int sendfile(int peer, int fd, off_t *offset, size_t n, size_t &left, size_t &copied, int ftype)
{
	off_t sbytes = 0;
	ssize_t r = 0, l = 0;

	// proc files
	if (ftype == FILE_PROC) {
		char buf[n], siz[32];
		r = pread(fd, buf, sizeof(buf), *offset);
		if (r < 0) {
			if (errno == EAGAIN)
				errno = EBADF;
			return -1;
		} else if (r > 0) {
			l = snprintf(siz, sizeof(siz), "%x\r\n", (int)r);
			if (writen(peer, siz, l) != l)
				return -1;
			if (writen(peer, buf, r) != r)
				return -1;
			if (writen(peer, "\r\n", 2) != 2)
				return -1;
			*offset += r;
			copied += r;
		} else {
			if (writen(peer, "0\r\n\r\n", 5) != 5)
				return -1;
			left = 0;
		}
		return 0;
	}


	if (ftype != FILE_DEVICE) {
		r = ::sendfile(fd, peer, *offset, n, NULL, &sbytes, 0);
		if (sbytes > 0) {
			*offset += sbytes;
			left -= sbytes;
			copied += sbytes;
		}
	// On FreeBSD, device files do not support sendfile()
	} else {
		char buf[n];
		r = pread(fd, buf, n, *offset);
		if (r > 0) {
			// write(), not writen()
			r = write(peer, buf, r);
			if (r > 0) {
				*offset += r;
				left -= r;
				copied += r;
			}
		}
		if (r <= 0)
			r = -1;
		else
			r = 0;
	}
	return (int)r;
}


} // namespace flavor


