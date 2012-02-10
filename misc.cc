/*
 * Copyright (C) 2008 Sebastian Krahmer.
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

#include <string>
#include <cstring>
#include <cstdio>
#include <ftw.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <fcntl.h>
#include "config.h"
#include "misc.h"


namespace NS_Misc {

using namespace std;

map<string, string> dir2index;
string err = "";

// if generated indexes exceed this limit, they
// are written as index.html to disk
const unsigned int index_max_size = 10000;

int ftw_helper(const char *fpath, const struct stat *st, int typeflag)
{
	char pathname[strlen(fpath) + 1];
	snprintf(pathname, sizeof(pathname), "%s", fpath);
	char *basename = strrchr(pathname, '/'), *parent = NULL;

	if (!basename)
		return 0;

	if (!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode) && !S_ISBLK(st->st_mode) &&
	    !S_ISLNK(st->st_mode))
		return 0;

	if (basename == pathname) {
		parent = (char *)"/";
		++basename;
	} else {
		*basename = 0;
		++basename;
		parent = pathname;
	}

	if (typeflag & FTW_D) {
		string html = "<html><head>\n";
		if (httpd_config::base.size() > 0) {
			html += "<base href=\"";
			html += httpd_config::base;
			html += "\">\n";
		}
		html += "<title>Index of ";
		html += fpath;
		html += "</title>\n";
		html += "</head>\n<body><h1>Index of ";
		html += fpath;
		html += "</h1>";
		html += "<table border=1><thead><tr><th></th><th>Name</th><th>Last modified</th><th>Size</th></tr>";
		html += "<th><img src=\"icons/back.png\" alt=\"[DIR]\"></th>";
		html += "<th><a href=\"";

		// If / is the parent, we need to use the base URL, since
		// otherwise it would be "/", which is not relative and wont
		// work with reverse proxy + <base> tag, which only works for
		// relative URLs
		if (strcmp(parent, "/") == 0)
			html += httpd_config::base;
		else
			html += parent + 1;
		html += "\">Parent Directory</a></th></tr></thead>";

		if (dir2index.find(fpath) == dir2index.end())
			dir2index[fpath] = html;

		if (dir2index.find(parent) != dir2index.end())
			html = dir2index[parent];
		if (!*basename)
			return 0;

		html += "<tr><th><img src=\"icons/folder.png\" alt=\"[DIR]\"></th>";
		html += "<th><a href=\"";
		html += fpath + 1;
		html += "\">";
		html += basename;
		html += "</th><th>";
		html += ctime(&st->st_mtime);
		html += "</th></tr>";

		dir2index[parent] = html;
	} else {
		string &html = dir2index[parent];
		html += "<tr><th><img src=\"icons/file.gif\" alt=\"[FILE]\"></th>";
		html += "<th><a href=\"";
		html += fpath + 1;
		html += "\">";
		html += basename;
		html += "</th><th>";
		html += ctime(&st->st_mtime);
		html += "</th><th>";
		char sbuf[128];
		// st is const
		off_t size = (off_t)st->st_size;
		if (S_ISBLK(st->st_mode)) {
			int fd = open(fpath, O_RDONLY);
			if (fd > 0) {
				ioctl(fd, BLKGETSIZE64, &size);
				close(fd);
			}
		}
		if (size > 1024*1024*1024)
			sprintf(sbuf, "%.2f GB", ((double)size)/(1024*1024*1024));
		else if (size > 1024*1024)
			sprintf(sbuf, "%.2f MB", ((double)size)/(1024*1024));
		else if (size > 1024)
			sprintf(sbuf, "%.2f KB", ((double)size)/1024);
		else
			sprintf(sbuf, "%zd B", size);

		html += sbuf;
		html += "</th></tr>";
	}
	return 0;
}


void generate_index(const string &path)
{
	map<string, string>::iterator i;
#ifdef linux
	ftw(path.c_str(), ftw_helper, 64);
#else
// FreeBSD returns error with nfd > OPEN_MAX
	ftw(path.c_str(), ftw_helper, 1);
#endif

	for (i = dir2index.begin(); i != dir2index.end();) {
		string &html = i->second;
		html += "</table><p id=\"bottom\"><a href=\"http://github.com/stealth/lophttpd\">lophttpd powered</a></p></body></html>";

		// if running multicore, only master needs to create files
		if (httpd_config::master && html.size() > index_max_size) {
			string path = i->first;
			path += "/index.html";
			int flags = O_RDWR|O_CREAT;

			// if running initial (root), dont smash existing stuff,
			// if USR1 is received, e.g. re-indexing, allow to update
			if (geteuid() == 0)
				flags |= O_EXCL;
			else
				flags |= O_TRUNC;
			int fd = open(path.c_str(), flags, 0644);
			if (fd < 0) {
				++i;
				continue;
			}
			write(fd, i->second.c_str(), i->second.size());

			// own to user, so re-generation of index files
			// can really happen
			fchown(fd, httpd_config::user_uid, httpd_config::user_gid);
			close(fd);

			// No iterator invalidation for associative containers
			dir2index.erase(i);
			i = dir2index.begin();
			continue;
		} else if (!httpd_config::master && html.size() > index_max_size) {
			dir2index.erase(i);
			i = dir2index.begin();
			continue;
		}
		++i;
	}
}


const char *why()
{
	return err.c_str();
}


}

