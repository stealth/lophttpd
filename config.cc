#include <cstdio>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iostream>
#include <map>
#include "config.h"

using namespace std;


namespace httpd_config
{
	string root = "/srv/www/htdocs", base = "/";
	string upload = "";
	string kfile = "", cfile = "";
	bool gen_index = 0, virtual_hosts = 0, is_chrooted = 0, quiet = 0;
	bool rand_upload = 0, no_error_kill = 0, rand_upload_quiet = 0, use_ssl = 0;
	string user = "wwwrun", logfile = "/var/log/lophttpd", log_provider = "file";
	uid_t user_uid = 99, user_gid = 99;
	string host = "0.0.0.0", port = "80";
	int cores = 1, af = AF_INET;

	// on multicore there is only one master
	int master = 1;

	uint16_t mss = 0;
	uint32_t max_connections = 10000;
	uint32_t ncache = 10000;
	int client_sched = 0;
}


namespace rproxy_config {

string err = "";

map<string, list<struct backend> > url_map;
map<string, string> location_map;
string user = "wwwrun", root = "/var/run/empty",
       logfile = "/var/log/frontend", host = "0.0.0.0", port = "80", location = "",
       logprovider = "file";


int parse(const string &cfile)
{
	FILE *f = fopen(cfile.c_str(), "r");
	if (!f) {
		err = "rproxy_config::parse::fopen:";
		err += strerror(errno);
		return -1;
	}

	char buf[1024], host[256], path[256], sport[32], *ptr = NULL;
	int r = 0;
	struct addrinfo *ai = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	while (fgets(buf, sizeof(buf), f)) {
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			++ptr;
		if (*ptr == '#' || *ptr == '\n')
			continue;

		if (strncmp(ptr, "map", 3) == 0) {
			ptr += 3;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;

			string opath = "";
			backend b;
			strtok(ptr, " \t\n#");
			opath = ptr;
			ptr = strtok(NULL, " \t\n#");

			memset(host, 0, sizeof(host));
			memset(path, 0, sizeof(path));
			if (strchr(ptr + 5, ':')) {
				if (sscanf(ptr, "http://%255[^:]:%hu/%255c", host, &b.port, path) == 0) {
					err = "rproxy_config::parse::sscanf: invalid 'map' config.";
					return -1;
				}
			} else {
				if (sscanf(ptr, "http://%255[^/]/%255c", host, path) == 0) {
				}
				b.port = 80;
			}

			b.host = host;
			b.path = "/";
			b.path += path;

			snprintf(sport, sizeof(sport), "%hu", b.port);
			if ((r = getaddrinfo(host, sport, &hints, &ai)) < 0) {
				err = "rproxy_config::parse::getaddrinfo:";
				err += gai_strerror(r);
				return -1;
			}
			b.ai = *ai;
			url_map[opath].push_back(b);
			location_map[ptr] = opath;
		} else if (strncmp(ptr, "user", 4) == 0) {
			ptr += 4;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			user = ptr;
		} else if (strncmp(ptr, "chroot", 6) == 0) {
			ptr += 6;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			root = ptr;
		} else if (strncmp(ptr, "logfile", 7) == 0) {
			ptr += 7;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			logfile = ptr;
		} else if (strncmp(ptr, "location", 8) == 0) {
			ptr += 8;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			location = ptr;
		} else if (strncmp(ptr, "notfound", 8) == 0) {
			// url, or default action wenn keine
		} else if (strncmp(ptr, "deny", 4) == 0) {
			// deny GET for regex
		} else if (strncmp(ptr, "host", 4) == 0) {
			ptr += 4;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			rproxy_config::host = ptr;
		} else if (strncmp(ptr, "port", 4) == 0) {
			ptr += 4;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			port = ptr;
		} else if (strncmp(ptr, "logprovider", 11) == 0) {
			ptr += 11;
			while (*ptr == ' ' || *ptr == '\t')
				++ptr;
			strtok(ptr, " \t\n#");
			logprovider = ptr;
		}
	}

	fclose(f);
	return 0;
}


const char *why()
{
	return err.c_str();
}


}

