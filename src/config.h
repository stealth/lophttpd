#ifndef lophttpd_config_h
#define lophttpd_config_h

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
	extern std::map<std::string, std::string> kfile, cfile;
	extern bool gen_index, virtual_hosts, is_chrooted, quiet, use_ssl, tfo;
	extern bool rand_upload, no_error_kill, rand_upload_quiet;
	extern std::string user, logfile, log_provider;
	extern uid_t user_uid, user_gid;
	extern std::string host, port;
	extern int cores, master;
	extern uint16_t mss;
	extern uint32_t max_connections;
	extern uint32_t ncache;
	extern int client_sched;
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

