#ifndef __config_h__
#define __config_h__

#include <map>
#include <string>
#include <list>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h>

namespace httpd_config
{
	extern std::string root, base;
	extern std::string upload;
	extern bool gen_index, virtual_hosts, is_chrooted, quiet;
	extern bool rand_upload, no_error_kill, rand_upload_quiet;
	extern std::string user, logfile, log_provider;
	extern uid_t user_uid, user_gid;
	extern std::string host, port;
	extern int cores, master, af;
	extern size_t mss;
}


namespace rproxy_config {


struct backend {
	std::string host, path;
	struct addrinfo ai;
	uint16_t port;
};


extern std::map<std::string, std::list<struct backend> > url_map;
extern std::map<std::string, std::string> location_map;
extern std::string user, root, logfile, host, port, location, logprovider;

int parse(const std::string &);

const char *why();

}

#endif

