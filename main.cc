/*
 * Copyright (C) 2008-2013 Sebastian Krahmer.
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
#include <signal.h>
#include <cstring>
#include "config.h"
#include "lonely.h"
#include "flavor.h"
#include "misc.h"
#include "multicore.h"

#ifdef USE_SSL_PRIVSEP
extern "C" {
#include "sslps.h"
#include "sslps_priv.h"
}
#endif

using namespace std;


void die(const char *s, bool please_die = 1)
{
	perror(s);
	if (please_die)
		exit(errno);
}


void help(const char *p)
{
	cerr<<"Usage: "<<p<<" [-6] [-R web-root] [-B html-base-tag] [-iH] [-I IP] [-u user]\n"
	    <<"\t\t [-l logfile] [-p port] [-L provider] [-n nCores] [-S n] [-s scheduler]\n"
	    <<"\t\t [-U upload] [-r] [-E] [-Q] [-N n] [-e n] [-K PEM-file] [-C PEM-file]\n\n"
	    <<"\tcommonly used options:\n\n"
	    <<"\t\t -R : web-root, default "<<httpd_config::root<<endl
	    <<"\t\t -i : use autoindexing\n"
	    <<"\t\t -I : IP(6) to bind to, default {INADDR_ANY}\n"
	    <<"\t\t -H : use vhosts (requires vhost setup in web-root)\n"
	    <<"\t\t -u : run as this user, default "<<httpd_config::user<<endl
	    <<"\t\t -n : number of CPU cores to use, default 1 ('0' for all)"<<endl
	    <<"\t\t -p : port, default "<<httpd_config::port<<endl<<endl
	    <<"\trarely used options:\n\n"
#ifdef USE_SSL
	    <<"\t\t -K : use this keyfile (enables SSL)\n"
	    <<"\t\t -C : use this certfile (enables SSL)\n"
#endif
	    <<"\t\t -6 : use IPv6, default is IPv4\n"
	    <<"\t\t -l : logfile, default "<<httpd_config::logfile<<endl
	    <<"\t\t -L : logprovider, default '"<<httpd_config::log_provider<<"'"<<endl
	    <<"\t\t -B : <base> 'http://...' tag, if operating behind a proxy\n"
	    <<"\t\t -q : quiet mode; don't generate any logs or index.html files\n"
	    <<"\t\t -S : sendfile() chunksize (no need to change), default: "<<DEFAULT_SEND_SIZE<<endl
	    <<"\t\t -N : maximum number of accepted clients, default: "<<httpd_config::max_connections<<endl
	    <<"\t\t -U : upload dir inside web-root, default disabled"<<endl
	    <<"\t\t -E : do not close connection on invalid requests, default disabled"<<endl
	    <<"\t\t -e : cache requests (at most n) that cause 404 errors, to save parsing next time seen"<<endl
	    <<"\t\t -s : scheduling algo for more than "<<MANY_RECEIVERS<<" clients (default 'none')"<<endl
	    <<"\t\t -Q : (implies -r) do not tell client the rand token (for write-only uploads)"<<endl
	    <<"\t\t -r : add rand token to uploaded filenames (default off)"<<endl<<endl;
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

static lonely_http *httpd = NULL;

void sigusr1(int x)
{
	if (!httpd)
		return;

	if (httpd_config::gen_index) {
		misc::dir2index.clear();
		if (httpd_config::is_chrooted)
			misc::generate_index("/");
		else
			misc::generate_index(httpd_config::root);
	}
	httpd->clear_cache();
}


#ifdef USE_SSL_PRIVSEP
extern "C" int privsep_init()
{
	if (chdir(httpd_config::root.c_str()) < 0)
		die("chdir");

	if (chroot(httpd_config::root.c_str()) < 0)
		die("chroot", 1);

	if (setgid(httpd_config::user_gid) < 0)
		die("setgid", 1);
	if (initgroups(httpd_config::user.c_str(), httpd_config::user_gid) < 0)
		die("initgroups", 1);
	if (setuid(httpd_config::user_uid) < 0)
		die("setuid", 1);

	return 0;
}
#endif


int main(int argc, char **argv)
{
	int c = 0;
	bool port_was_given = 0;

	cout<<"\nlophttpd -- lots of performance httpd (C) 2008-2013 Sebastian Krahmer\n\n";

	if (getuid() != 0) {
		cerr<<"\a!!! WARNING: !!! Must be called as root in order to chroot() and drop privs properly!\n";
		cerr<<"Continuing in UNSAFE mode!\n\n";
	}

	while ((c = getopt(argc, argv, "iHhR:p:l:L:u:n:S:I:6B:qU:rEQN:C:K:e:s:")) != -1) {
		switch (c) {
		case '6':
			if (httpd_config::host == "0.0.0.0")
				httpd_config::host = "::";
			break;
		case 'i':
			httpd_config::gen_index = 1;
			break;
		case 'R':
			httpd_config::root = optarg;
			break;
		case 'H':
			httpd_config::virtual_hosts = 1;
			break;
		case 'u':
			httpd_config::user = optarg;
			break;
		case 'I':
			httpd_config::host = optarg;
			break;
		case 'p':
			httpd_config::port = optarg;
			port_was_given = 1;
			break;
		case 'l':
			httpd_config::logfile = optarg;
			break;
		case 'L':
			httpd_config::log_provider = optarg;
			break;
		case 'n':
			httpd_config::cores = strtoul(optarg, NULL, 10);
			break;
		case 'S':
			httpd_config::mss = strtoul(optarg, NULL, 10);
			break;
		case 'B':
			httpd_config::base = optarg;
			break;
		case 'q':
			httpd_config::quiet = 1;
			break;
		case 'U':
			httpd_config::upload = optarg;
			break;
		case 'r':
			httpd_config::rand_upload = 1;
			break;
		case 'Q':
			httpd_config::rand_upload = 1;
			httpd_config::rand_upload_quiet = 1;
			break;
		case 'E':
			httpd_config::no_error_kill = 1;
			break;
		case 'e':
			httpd_config::ncache = strtoul(optarg, NULL, 10);
			break;
		case 'N':
			httpd_config::max_connections = strtoul(optarg, NULL, 10);
			break;
		case 'K':
			httpd_config::kfile = optarg;
			break;
		case 'C':
			httpd_config::cfile = optarg;
			break;
		case 's':
			if (strcmp(optarg, "none") == 0)
				httpd_config::client_sched = CLIENT_SCHED_NONE;
			if (strcmp(optarg, "static") == 0)
				httpd_config::client_sched = CLIENT_SCHED_STATIC;
			else if (strcmp(optarg, "suspend") == 0)
				httpd_config::client_sched = CLIENT_SCHED_SUSPEND;
			else if (strcmp(optarg, "minimize") == 0)
				httpd_config::client_sched = CLIENT_SCHED_MINIMIZE;
			else
				help(*argv);
			break;
		case 'h':
		default:
			help(*argv);
		}
	}

	cout<<"Using webroot '"<<httpd_config::root<<"' and user '"<<httpd_config::user
	    <<"'.\nRun with '-h' if you need help. Starting up ...\n\n";

	uid_t euid = geteuid();

	tzset();
	nice(-20);
	close_fds();

	if (httpd_config::mss == 0)
		httpd_config::mss = DEFAULT_SEND_SIZE;

	httpd = new (nothrow) lonely_http(httpd_config::mss);
	if (!httpd) {
		cerr<<"OOM: Cannot create webserver object!\n";
		return -1;
	}

	struct passwd *pw = getpwnam(httpd_config::user.c_str());
	if (!pw) {
		cerr<<"Fatal: Unknown user '"<<httpd_config::user<<"'. Exiting.\n";
		return -1;
	}
	httpd_config::user_uid = pw->pw_uid;
	httpd_config::user_gid = pw->pw_gid;

	if (httpd_config::cfile.size() && httpd_config::kfile.size()) {
		if (!port_was_given)
			httpd_config::port = "443";
		httpd_config::use_ssl = 1;
		if (httpd->setup_ssl(httpd_config::cfile, httpd_config::kfile) < 0) {
			cerr<<"Unable to initialize SSL, exiting:\n";
			cerr<<httpd->why()<<endl;
			return -1;
		}
	}

	if (httpd->init(httpd_config::host, httpd_config::port) < 0) {
		cerr<<httpd->why()<<endl;
		return -1;
	}

	// Needs to be called before chroot
	misc::init_multicore();
	misc::setup_multicore(httpd_config::cores);

	// Every core has its own logfile to avoid locking
	if (!httpd_config::quiet) {
		if (httpd->open_log(httpd_config::logfile, httpd_config::log_provider, misc::my_core) < 0) {
			cerr<<"ERROR: opening logfile: "<<httpd->why()<<endl;
			cerr<<"continuing without logging!\n";
		}
	}

	if (chdir(httpd_config::root.c_str()) < 0)
		die("chdir");

	if (chroot(httpd_config::root.c_str()) < 0) {
		die("chroot", euid == 0);
	} else
		httpd_config::is_chrooted = 1;

	if (httpd_config::gen_index) {
		if (httpd_config::is_chrooted)
			misc::generate_index("/");
		else
			misc::generate_index(httpd_config::root);
	}

	if (setgid(httpd_config::user_gid) < 0)
		die("setgid", euid == 0);
	if (initgroups(httpd_config::user.c_str(), httpd_config::user_gid) < 0)
		die("initgroups", euid == 0);
	if (setuid(httpd_config::user_uid) < 0)
		die("setuid", euid == 0);

#ifdef USE_SSL_PRIVSEP
	if (SSL_privsep_ctrl(PRIVSEP_DROP_PRIV) < 0)
		die("SSL_privsep_ctrl");
#endif

	if (httpd_config::virtual_hosts)
		httpd->vhosts = 1;

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

	if (httpd_config::master) {
		if (fork() > 0)
			exit(0);
		setsid();
	}

	if (flavor::sandbox() < 0) {
		httpd->log("Exit: error setting up sandbox");
		exit(1);
	}

	httpd->loop();

#ifdef USE_SSL_PRIVSEP
	SSL_privsep_ctrl(PRIVSEP_EXIT);
#endif

	delete httpd;
	return 0;
}

