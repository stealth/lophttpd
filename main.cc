/*
 * Copyright (C) 2008-2011 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <cstring>
#include "lonely.h"
#include "misc.h"
#include "multicore.h"


using namespace std;


namespace Config
{
	string root = "/srv/www/htdocs";
	bool gen_index = 0, virtual_hosts = 0, is_chrooted = 0;
	string user = "wwwrun", logfile = "/var/log/lophttpd", log_provider = "file";
	uid_t user_uid = 99, user_gid = 99;
	uint16_t port = 80;
	uint16_t log_granularity = 3;
	int cores = -1;

	// on multicore there is only one master
	int master = 1;
}


void die(const char *s, bool please_die = 1)
{
	perror(s);
	if (please_die)
		exit(errno);
}


void help(const char *p)
{
	cerr<<"Usage: "<<p<<" [-R web-root] [-i] [-H] [-h] [-u user] [-l logfile] [-p port] [-L provider] [-n nCores]\n\n"
	    <<"\t\t -R : web-root, default "<<Config::root<<endl
	    <<"\t\t -i : use autoindexing\n"
	    <<"\t\t -H : use vhosts (requires vhost setup in web-root)\n"
	    <<"\t\t -h : this help\n"
	    <<"\t\t -u : run as this user, default "<<Config::user<<endl
	    <<"\t\t -l : logfile, default "<<Config::logfile<<endl
	    <<"\t\t -L : logprovider, default "<<Config::log_provider<<endl
	    <<"\t\t -n : number of CPU cores to use, default all"<<endl
	    <<"\t\t -p : port, default "<<Config::port<<endl;
	exit(errno);
}


void close_fds()
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		die("getrlimit");
	for (unsigned int i = 3; i <= rl.rlim_max; ++i)
		close(i);
	close(0);
	open("/dev/null", O_RDWR);
	dup2(0, 1);
}

static lonely_http httpd;

void sigusr1(int x)
{
	if (Config::gen_index) {
		NS_Misc::dir2index.clear();
		if (Config::is_chrooted)
			NS_Misc::generate_index("/");
		else
			NS_Misc::generate_index(Config::root);
	}
	httpd.clear_cache();
}


int main(int argc, char **argv)
{
	int c = 0;
	cout<<"\nlophttpd -- lonely & poor httpd (C) 2008-2011 Sebastian Krahmer\n\n";

	if (getuid() != 0) {
		cerr<<"\a!!! WARNING: !!! Must be called as root in order to chroot() and drop privs properly!\n";
		cerr<<"Continuing in UNSAFE mode!\n\n";
	}

	while ((c = getopt(argc, argv, "iHhR:p:l:L:u:n:")) != -1) {
		switch (c) {
		case 'i':
			Config::gen_index = 1;
			break;
		case 'R':
			Config::root = optarg;
			break;
		case 'H':
			Config::virtual_hosts = 1;
			break;
		case 'u':
			Config::user = optarg;
			break;
		case 'p':
			Config::port = strtoul(optarg, NULL, 10);
			break;
		case 'l':
			Config::logfile = optarg;
			break;
		case 'L':
			Config::log_provider = optarg;
			break;
		case 'n':
			Config::cores = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			help(*argv);
		}
	}

	uid_t euid = geteuid();

	tzset();
	nice(-20);
	close_fds();

	if (httpd.init(Config::port) < 0) {
		cerr<<httpd.why()<<endl;
		return -1;
	}

	// Needs to be called before chroot
	NS_Misc::init_multicore();
	NS_Misc::setup_multicore(Config::cores);

	// Every core has its own logfile to avoid locking
	if (httpd.open_log(Config::logfile, Config::log_provider, NS_Misc::my_core) < 0) {
		cerr<<"Opening logfile: "<<httpd.why()<<endl;
		return -1;
	}

	struct passwd *pw = getpwnam(Config::user.c_str());
	if (!pw) {
		cerr<<"Fatal: Unknown user '"<<Config::user<<"'. Exiting.\n";
		return -1;
	}
	Config::user_uid = pw->pw_uid;
	Config::user_gid = pw->pw_gid;

	if (chdir(Config::root.c_str()) < 0)
		die("chdir");

	if (chroot(Config::root.c_str()) < 0) {
		die("chroot", euid == 0);
	} else
		Config::is_chrooted = 1;

	if (Config::gen_index) {
		if (Config::is_chrooted)
			NS_Misc::generate_index("/");
		else
			NS_Misc::generate_index(Config::root);
	}


	if (setgid(pw->pw_gid) < 0)
		die("setgid", euid == 0);
	if (initgroups(Config::user.c_str(), pw->pw_gid) < 0)
		die("initgroups", euid == 0);
	if (setuid(pw->pw_uid) < 0)
		die("setuid", euid == 0);

	if (Config::virtual_hosts)
		httpd.vhosts = 1;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0)
		die("sigaction");

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		die("sigaction");

	dup2(0, 2);

	if (Config::master) {
		if (fork() > 0)
			exit(0);
		setsid();
	}

	httpd.loop();

	return 0;
}

