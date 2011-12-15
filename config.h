#ifndef __config_h__
#define __config_h__

#include <string>
#include <sys/types.h>
#include <stdint.h>

namespace Config
{
	extern std::string root;
	extern bool gen_index, virtual_hosts, is_chrooted;
	extern std::string user, logfile;
	extern uid_t user_uid, user_gid;
	extern std::string host, port;
	extern int cores, master, af;
	extern size_t mss;
}

#endif

