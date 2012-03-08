#include <string>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include "flavor.h"


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
	return S_ISCHR(st.st_mode);
}


bool servable_file(const struct stat &st)
{
	// no S_ISLNK() since stat() was used
	return S_ISCHR(st.st_mode) || S_ISREG(st.st_mode) || S_ISDIR(st.st_mode);
}


int device_size(const std::string &path, size_t &size, char &sendfile)
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

	sendfile = 0;
	return r;
}


int sendfile(int peer, int fd, off_t *offset, size_t n, size_t &left, size_t &copied, bool can_sendfile)
{
	off_t sbytes = 0;
	ssize_t r = 0;

	if (can_sendfile) {
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
			r = write(cur_peer, buf, r);
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


