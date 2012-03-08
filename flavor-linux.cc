#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <string>
#include <fcntl.h>
#include <errno.h>
#include <sys/sendfile.h>

#include "flavor.h"


namespace flavor {

int accept(int fd, struct sockaddr *saddr, socklen_t *slen, int flags)
{
	return accept4(fd, saddr, slen, flags == NONBLOCK ? SOCK_NONBLOCK : 0);
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


} // namespace flavor

