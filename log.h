#ifndef __log_h__
#define __log_h__

#include <string>
#include <sys/types.h>
#include <aio.h>

class log_provider {
private:
	int log_fd;
	struct aiocb log_aio;
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

	int open_log(const std::string &, const std::string &);

	log_provider() {};

	~log_provider();
};

#endif

