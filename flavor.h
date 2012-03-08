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

int accept(int, struct sockaddr *, socklen_t *, int);

bool servable_device(const struct stat &);

bool servable_file(const struct stat &);

int device_size(const std::string &, size_t &, char &);

// calls sendfile() if can_sendfile indicates that. returns 0 on success, -1 on error.
// uses normal read/write if sendfile cannot be used. updates offset, left and copied accordingly
int sendfile(int peer, int fd, off_t *offset, size_t n, size_t &left, size_t &copied, bool can_sendfile);

}

#endif // __flavor_h__

