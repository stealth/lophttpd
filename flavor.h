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


#ifndef __flavor__
#define __flavor__

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>

namespace flavor {

enum {
	NONBLOCK = 1
};


// return a (unblocking if NONBLOCK flag is set) accepted socket
int accept(int, struct sockaddr *, socklen_t *, int);

bool servable_device(const struct stat &);

bool servable_file(const struct stat &);

int device_size(const std::string &, size_t &);

// calls sendfile() if !is_dev indicates that. returns 0 on success, -1 on error.
// uses normal read/write if sendfile cannot be used. updates offset, left and copied accordingly
int sendfile(int peer, int fd, off_t *offset, size_t n, size_t &left, size_t &copied, bool is_dev);

}

#endif // __flavor_h__

