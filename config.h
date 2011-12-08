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
	extern uint16_t port;
	extern int cores, master;
	extern size_t mss;
}

#endif

