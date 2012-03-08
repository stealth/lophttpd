#include <fcntl.h>
#include <errno.h>
#include <string>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include "flavor.h"

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12,114,size_t)
#endif

namespace flavor {

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
	return S_ISBLK(st.st_mode);
}


bool servable_file(const struct stat &st)
{
	// no S_ISLNK() since stat() was used
	return S_ISBLK(st.st_mode) || S_ISREG(st.st_mode) || S_ISDIR(st.st_mode);
}


int device_size(const std::string &path, size_t &size, char &sendfile)
{
	int fd = ::open(path.c_str(), O_RDONLY|O_NOCTTY);
	if (fd < 0)
		return -1;

	int r = 0, saved_errno = 0;
	if (ioctl(fd, BLKGETSIZE64, &size) < 0) {
		r = -1;
		saved_errno = errno;
	}
	close(fd);
	errno = saved_errno;
	return r;
}


int sendfile(int peer, int fd, off_t *offset, size_t n, size_t &left, size_t &copied, bool can_sendfile)
{
	// Linux can, unlike BSD, use sendfile() on device files, so
	// the last parameter is ignored
	ssize_t r = 0;
	if ((r = ::sendfile(peer, fd, offset, n)) < 0)
		return -1;
	left -= r;
	copied += r;
	return 0;
}

}

