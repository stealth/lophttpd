/*
 * Copyright (C) 2008-2014 Sebastian Krahmer.
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
#include <cstdlib>
#include <cerrno>
#include <cstdio>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <fcntl.h>
#include "config.h"
#include "misc.h"
#include "flavor.h"


// Android has got not ftw! So we need to write our own

namespace misc {

using namespace std;

enum {
	FTW_D = 1,
	FTW_F = 2,
	FTW_L = 4
};

struct ctypes content_types[] = {
	// This one must be at index 0 and 1, since we keep a cache of
	// file <-> content-type with an index to this table
	{".data", "application/data"},
	{".html", "text/html"},

	{".apk", "application/vnd.android.package-archive"},
	{".avi", "video/x-msvideo"},
	{".bmp", "image/bmp"},
	{".bib", "text/x-bibtex"},
	{".c", "text/x-csrc"},
	{".cc", "text/x-c++src"},
	{".cpp", "text/x-c++src"},
	{".cxx", "text/x-c++src"},
	{".css", "text/css"},
	{".dtd", "text/x-dtd"},
	{".dvi", "application/x-dvi"},
	{".fig", "image/x-xfig"},
	{".flv", "application/flash-video"},
	{".gif", "image/gif"},
	{".gz", "application/gzip"},
	{".h", "text/x-chdr"},
	{".hh", "text/x-chdr"},
	{".htm", "text/html"},
	{".ico", "image/x-ico"},
	{".iso", "application/x-cd-image"},
	{".java", "text/x-java"},
	{".jpg", "image/jpg"},
	{".js", "application/x-javascript"},
	{".mp3", "audio/mpeg"},
	{".mpeg", "video/mpeg"},
	{".mpg", "video/mpeg"},
	{".ogg", "application/ogg"},
	{".pac", "application/x-ns-proxy-autoconfig"},
	{".pdf", "application/pdf"},
	{".pls", "audio/x-scpls"},
	{".png", "image/png"},
	{".ps", "application/postscript"},
	{".ps.gz", "application/x-gzpostscript"},
	{".rar", "application/x-rar-compressed"},
	{".rdf", "text/rdf"},
	{".rss", "text/rss"},
	{".sgm", "text/sgml"},
	{".sgml", "text/sgml"},
	{".svg", "image/svg+xml"},
	{".tar", "application/x-tar"},
	{".tar.Z", "application/x-tarz"},
	{".tgz", "application/gzip"},
	{".tiff", "image/tiff"},
	{".txt", "text/plain"},
	{".wav", "audio/x-wav"},
	{".wmv", "video/x-ms-wm"},
	{".xbm", "image/x-xbitmap"},
	{".xml", "text/xml"},
	{".zip", "application/zip"},
	{".zoo", "application/x-zoo"},
	{"", ""}
};

map<string, string> dir2index;
string err = "";


int find_ctype(const string &p)
{
	int i = 0;

	for (i = 0; !content_types[i].extension.empty(); ++i) {
		if (p.size() <= content_types[i].extension.size())
			continue;
		if (strcasestr(p.c_str()+p.size() - content_types[i].extension.size(),
        	       content_types[i].extension.c_str()))
			break;
	}
	if (content_types[i].c_type.empty())
		i = 0;
	return i;
}


// if generated indexes exceed this limit, they
// are written as index.html to disk
const unsigned int index_max_size = 1<<24;


int ftw_helper(const char *fpath, const struct stat *st, int typeflag)
{
	string pathname = fpath, parent = "";

	if (pathname.find("//") != string::npos || pathname.find("/../") != string::npos ||
	    pathname.find("/./") != string::npos)
		return -1;

	string::size_type base = pathname.find_last_of("/");
	string basename = "";
	char spaces[40];

	if (base == string::npos)
		return 0;

	if (!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode) && !S_ISBLK(st->st_mode) &&
	    !S_ISLNK(st->st_mode) && !S_ISCHR(st->st_mode))
		return 0;

	if (base == 0) {
		parent = "/";
		basename = pathname.substr(1);
	} else {
		basename = pathname.substr(base + 1);
		parent = pathname.substr(0, base);
	}

	memset(spaces, ' ', sizeof(spaces) - 1);
	spaces[sizeof(spaces) - 1] = 0;

	char *mod_time = ctime((const time_t *)&st->st_mtime), *nl = NULL;
	if ((nl = strchr(mod_time, '\n')) != NULL)
		*nl = 0;

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
		html += "</h1><pre>";
		html += "Name                                           Last modified                Size    Content\n<hr>\n";
		html += "[DIR ] <a href=\"";

		// If / is the parent, we need to use the base URL, since
		// otherwise it would be "/", which is not relative and wont
		// work with reverse proxy + <base> tag, which only works for
		// relative URLs
		if (parent == "/")
			html += httpd_config::base;
		else
			html += parent.substr(1);
		html += "\">Parent Directory</a>\n\n";

		if (dir2index.find(fpath) == dir2index.end())
			dir2index[fpath] = html;

		if (dir2index.find(parent) != dir2index.end())
			html = dir2index[parent];
		if (basename == "")
			return 0;

		html += "[DIR ]";
		html += " <a href=\"";
		html += fpath + 1;
		html += "\">";
		html += basename;
		html += "</a>";
		if (basename.size() < sizeof(spaces))
			html += string(spaces, sizeof(spaces) - basename.size());
		else
			html += "  ";

		html += mod_time;
		html += string(spaces, 13);	// size
		html += "(directory)\n";

		dir2index[parent] = html;
	} else if (typeflag & FTW_L) {
		char lnk[1024], rlnk[4096];
		memset(lnk, 0, sizeof(lnk));
		memset(rlnk, 0, sizeof(rlnk));
		if (readlink(fpath, lnk, sizeof(lnk)) < 0)
			return -1;
		if (!realpath(lnk, rlnk))
			return -1;
		string &html = dir2index[parent];
		html += "[FILE]";
		html += " <a href=\"";
		html += rlnk + 1;
		html += "\">";
		html += basename;
		html += "</a>";
		if (basename.size() < sizeof(spaces))
			html += string(spaces, sizeof(spaces) - basename.size());
		else
			html += "  ";
		html += mod_time;
		html += string(spaces, 13);	// size
		html += "(symlink)\n";
	} else {
		string &html = dir2index[parent];
		html += "[FILE]";
		html += " <a href=\"";
		html += fpath + 1;
		html += "\">";
		html += basename;
		html += "</a>";
		if (basename.size() < sizeof(spaces))
			html += string(spaces, sizeof(spaces) - basename.size());
		else
			html += "  ";
		html += mod_time;
		char sbuf[128];
		// st is const
		off_t size = st->st_size;
		if (!size && flavor::servable_device(*st)) {
			flavor::device_size(fpath, size);
		}
		if (size > 1024*1024*1024)
			sprintf(sbuf, " %8.2fGB  ", ((double)size)/(1024*1024*1024));
		else if (size > 1024*1024)
			sprintf(sbuf, " %8.2fMB  ", ((double)size)/(1024*1024));
		else if (size > 1024)
			sprintf(sbuf, " %8.2fKB  ", ((double)size)/1024);
		else
			sprintf(sbuf, " %8zdB   ", (size_t)size);

		html += sbuf;
		int i = find_ctype(basename);
		html += content_types[i].c_type;
		html += "\n";
	}
	return 0;
}



int ftw_once(const char *dir, int (*fn) (const char *fpath, const struct stat *sb, int typeflag), int nopenfd)
{
	DIR *dfd = NULL;
	string pathname = "";
	struct dirent dent, *res = NULL;
	struct stat lst;

	if ((dfd = opendir(dir)) == NULL)
		return -1;

	for (;;) {
		if (readdir_r(dfd, &dent, &res) < 0)
			break;
		if (!res)
			break;
		if (strcmp(dent.d_name, ".") == 0 || strcmp(dent.d_name, "..") == 0)
			continue;
		pathname = dir;
		if (pathname[pathname.size() - 1] != '/')
			pathname += "/";
		pathname += dent.d_name;

		if (lstat(pathname.c_str(), &lst) < 0)
			continue;
		// dont follow symlinks into directories
		if (S_ISDIR(lst.st_mode)) {
			fn(pathname.c_str(), &lst, FTW_D);
			ftw_once(pathname.c_str(), fn, 1);
		} else if (S_ISLNK(lst.st_mode)) {
			fn(pathname.c_str(), &lst, FTW_L);
		} else {
			fn(pathname.c_str(), &lst, FTW_F);
		}
	}
	closedir(dfd);
	return 0;
}


// nopenfd is ignored
int ftw(const char *dir, int (*fn) (const char *fpath, const struct stat *sb, int typeflag), int nopenfd)
{
	struct stat st;

	// This function is only to also record the real parent dir
	// without having it processed inrecursive calls ever and ever
	if (stat(dir, &st) < 0)
		return -1;
	fn(dir, &st, FTW_D);

	return ftw_once(dir, fn, nopenfd);
}


void generate_index(const string &path)
{
	map<string, string>::iterator i;

	ftw(path.c_str(), ftw_helper, 1);

	uid_t euid = geteuid();

	for (i = dir2index.begin(); i != dir2index.end();) {
		string &html = i->second;
		html += "</pre><hr><p id=\"bottom\"><a href=\"http://github.com/stealth/lophttpd\">lophttpd powered</a></p></body></html>";

		// in quiet mode, dont drop index.html files
		if (httpd_config::quiet) {
			++i;
			continue;
		}

		// if running multicore, only master needs to create files
		if (httpd_config::master && html.size() > index_max_size) {
			string path = i->first;
			path += "/index.html";
			int flags = O_RDWR|O_CREAT;

			// if running initial (root), dont smash existing stuff,
			// if USR1 is received, e.g. re-indexing, allow to update
			if (euid == 0)
				flags |= O_EXCL;
			else
				flags |= O_TRUNC;
			int fd = open(path.c_str(), flags, 0644);
			if (fd < 0) {
				if (errno == EEXIST)
					dir2index.erase(i++);
				else
					++i;
				continue;
			}
			write(fd, i->second.c_str(), i->second.size());

			// own to user, so re-generation of index files
			// can really happen
			if (euid == 0)
				fchown(fd, httpd_config::user_uid, httpd_config::user_gid);
			close(fd);

			dir2index.erase(i++);
			continue;
		} else if (!httpd_config::master && html.size() > index_max_size) {
			dir2index.erase(i++);
			continue;
		}
		++i;
	}
}


const char *why()
{
	return err.c_str();
}


} // namespace misc

