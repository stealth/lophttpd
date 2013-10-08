/*
 * Copyright (C) 2012-2013 Sebastian Krahmer.
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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
//#include <sys/prctl.h>
//#include <sys/capability.h>
#include <signal.h>
#include <cstring>
#include "config.h"
#include "lonely.h"
#include "rproxy.h"
#include "misc.h"
#include "multicore.h"


using namespace std;


void die(const char *s, bool please_die = 1)
{
	perror(s);
	if (please_die)
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


static rproxy *proxy = NULL;

void sigusr1(int x)
{
	if (!proxy)
		return;
}


int main(int argc, char **argv)
{
	if (getuid() != 0) {
		cerr<<"\a!!! WARNING: !!! Must be called as root in order to chroot() and drop privs properly!\n";
		cerr<<"Continuing in UNSAFE mode!\n\n";
	}

	uid_t euid = geteuid();

	if (argc != 2) {
		cerr<<"Usage: frontend <config-file>\n";
		return 1;
	}

	if (rproxy_config::parse(argv[1]) < 0) {
		cerr<<rproxy_config::why()<<endl;
		return -1;
	}

	tzset();
	nice(-20);
	close_fds();

	proxy = new (nothrow) rproxy();

	if (proxy->open_log(rproxy_config::logfile, rproxy_config::logprovider, 0) < 0) {
		cerr<<"Opening logfile: "<<proxy->why()<<endl;
		return -1;
	}

	if (proxy->init(rproxy_config::host, rproxy_config::port) < 0) {
		proxy->log(proxy->why());
		exit(-1);
	}

	struct passwd *pw = getpwnam(rproxy_config::user.c_str());
	if (!pw) {
		cerr<<"Fatal: Unknown user '"<<rproxy_config::user<<"'. Exiting.\n";
		return -1;
	}

#if 0
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
		die("prctl");
#endif

	chdir("/");
	if (chroot(rproxy_config::root.c_str()) < 0)
		die("chroot", euid == 0);

	if (setgid(pw->pw_gid) < 0)
		die("setgid", euid == 0);
	if (initgroups(rproxy_config::user.c_str(), pw->pw_gid) < 0)
		die("initgroups", euid == 0);
	if (setuid(pw->pw_uid) < 0)
		die("setuid", euid == 0);
#if 0
	cap_t my_caps;
	cap_value_t cv[2] = {CAP_NET_ADMIN, CAP_NET_BIND_SERVICE};

	if ((my_caps = cap_init()) == NULL)
		die("cap_init");
	if (cap_set_flag(my_caps, CAP_EFFECTIVE, 2, cv, CAP_SET) < 0)
		die("cap_set_flag");
	if (cap_set_flag(my_caps, CAP_PERMITTED, 2, cv, CAP_SET) < 0)
		die("cap_set_flag");
	if (cap_set_proc(my_caps) < 0)
		die("cap_set_proc");
	cap_free(my_caps);
#endif

	if (chdir("/") < 0)
		die("chdir");

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0)
		die("sigaction");

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
		die("sigaction");

	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		die("sigaction");

	dup2(0, 2);

	if (fork() > 0)
		exit(0);

	setsid();

	for (;;) {
		if (proxy->loop() < 0)
			proxy->log(proxy->why());
	}

	delete proxy;
	return 0;
}

