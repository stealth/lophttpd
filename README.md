lophttpd: lots of performance httpd
===================================

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9MVF8BRMX2CWA)

Intro
-----

_lophttpd_ was written to demonstrate (to myself) that it is possible
to have a web-server running in a single thread and handling multiple
connections at the same time. The amount of connections is only limited by the
OS's maximum number of open files per process and by your CPU/network
speed.

_lophttpd_ can easily serve 10,000+ clients simulteanously and just
using 70% CPU on an average sized machine (tested on a core i5).

Scheduling of connections is done in user-space by _lophttpd_. It uses the
`sendfile(2)` call and caching to get its good download performance.

_lophttpd_ can be used to serve heavy loaded sites to deliver static content:
To serve software/package repositories, update servers, content delivery
networks, ISO's, large image and video databases, tar-balls etc.
It also comes with _frontend_ reverse proxy that achieves the same performance
on the (proxied) landing page as _lophttpd_ will in the backend.
_frontend_ also has built-in load balancing on the HTTP layer.


By using the OpenSSL library functions, this product uses software developed
by the [OpenSSL Project](https://www.openssl.org) for use in the OpenSSL Toolkit.


Features
--------

* runs as unprived user in a chroot
* IPv6 ready
* https support
* does not require syslogd
* supports multiple log-providers (`mmap` is very fast)
* only handles static content (e.g. no CGI scripts etc)
* runs in a single process
* multi-core support for Linux
* integrated auto indexing support
* vhost support (for TLS also with SNI)
* can operate behind reverse proxy with -B
* can serve block device files (whole HDD's), /sys and /proc files
* does not need config files and has a quiet mode (Android)
* native file upload support via PUT (default disabled)
* runs on Linux, BSD, OSX and Android
* transparent seccomp sandbox support for Linux
* comes with a separate frontend revproxy that also supports load balancing

Build
-----

Check the `Makefile` for the platform of your choice and enable or disable stuff
you want to use (e.g. sandboxing or [LibreSSL](https://www.libressl.org) or do not want or just leave it as is.

```
$ cd src
```

If you want TLS support with ephemeral keying:

```
src $ ./newdh
```

then for Linux:

```
src $ make
```

If you have GNU-make installed on BSDish systems:

```
src $ gmake
```

otherwise you can:

```
src $ make -f Makefile.bsd
```


and so on.


Run
---

You should run _lophttpd_ as root. Then it chroots itself to the
`-R` parameter given on the command-line and drops the privileges
to that of the user given via `-u`. It runs on port `-p`.
If you add `-i` to the command-line, it generates an index file
(in memory) for the web-root recursively. The user specified via `-u`
must have the permissions to walk the web-root, otherwise
you will get wrong results. If you use `-i`, you probably want
to copy the __icons/__ directory to your web-root, to have a pretty
output. The icons are not by me, I grabbed them from some distro
and they seem to be public domain.


Virtual Hosting
---------------

`-H` enables vhosts.

For every vhost you need to create a subdir of name

    vhost<vhost-name>[:vhost-port]

If port is `80` it should be omitted. For example if you
have a vhost `localhost:8080` and your web-root is __/srv/www/htdocs__
and you want to use auto-indexing, create the subdir

    vhostlocalhost:8080

inside __/srv/www/htdocs__ and run

    # ./lhttpd -R /srv/www/htdocs -i -H -p 8080

Users can browse `localhost:8080` then. Whatever they type in the address field
of their browser can be appended to "vhost" and created as a subdir.
_lophttpd_ will serve this as a vhost as long as your DNS resolves
to the IP address where _lophttpd_ is running.

If you are using vhosts with TLS, you may want to use the SNI feature.
_lophttpd_ is using this automatically if you provide additional certificates
for each vhost, in the form of  `vhost:certpath`

    # ./lhttpd -C pub.x509 -K key.pem -C localhost:pub1.x509 -K localhost:key1.pem -H -i

The __pub.x509__ is the default certificate presented to the client if its not
supporting SNI or requesting hosts that are not served. In case the client indicates
__localhost__ via SNI, it will be presented the certificate from __pub1.x509__


The default log-location is __/var/log/lophttpd__. If you change this, take care
that your log-file is located outside the chroot cage.

You can run _lophttpd_ as normal user on a port >= 1024, but this is INSECURE!
It does not drop privs/chroot then. The aim is to quickly exchange some
ISO's or tar-balls in a separated, secure LAN between friends.

If you change something in the web-root while lophttpd is running,
e.g. you use auto-indexing and copy new files to web-root or
delete files from there, you need to tell lophttpd by sending
it a `SIGUSR1` signal. It will drop its open file caches and
generates new indexes.


Misc
----

If `lhttpd` experiences that the generated indexes exceed a certain limit,
(default 16MB bytes per dir) it writes the appropriate __index.html__ to disk
inside the directory. It wont overwrite existing files. But creation of
large index files makes sense, otherwise it would need to keep 100's
of MB inside RAM. Since `lhttpd` is walking the web-root as root when
generating the index, take care that users don't create large FS-trees
so that `lhttpd` is forced to generate junk.
Generating indexes for large directories, containing 100k of files, can
take some time. If the `-q` parameter is passed, generated indexes
are NOT written to disk and logs are not written. This is to run in a clean
mode on Android devices without leaving any trace if you do forensics
on the device, since _lophttpd_ allows you to download whole partitions
as block devices.

Since version 0.82 _lophttpd_ contains an experimental feature to
speed up logging. Since writing 1000's of logs per second can
be a bottleneck, _lophttpd_ introduces different log providers
which you can choose via `-L`.
By default it is `file` which means the normal behavior. You can
also say `mmap` Then it is using a mmap-backed buffer which speeds
up logging. `aio` is also supported which uses the POSIX real-time
`aio_` calls. However this could lead to drops of messages if
under very heavy load. Remember that _lophttpd_ is still single threaded,
even with different log providers. (For aio to be really
single threaded you may want to check out my Linux aio implementation
since glibc is using pthreads under the hood.)


Multicore support
-----------------

Since version 0.86 _lophttpd_ supports multi-core setups for Linux.
If run without any `-n` switch, _lophttpd_ will run one process per core.
You can turn this off by using `-n 1` or you specify the number
of cores you want lophttpd to use. In general, `-n 1` is a good idea,
since even if under heavy load, you rarely need more than one core
for _lophttpd_.

Since version 0.88 _lophttpd_ has one log-file per core. If you run on two
cores you get __logfile.0__ and __logfile.1__. This way we avoid file locking.
_lophttpd_ is now also using local-time instead of gmtime in the logs,
so take care to have the right TZ environment variable set when starting
`lhttpd` or it will use UTC.

If you use multi-core support, every process will have its own cache
for open files and stats. Do not run `lhttpd` on large read-only directories w/o
__index.html__ and auto-indexing since it needs to keep a big cache about
indexing information in memory then (per core!). This does not happen
if the directory is writable since _lophttpd_ will dump content into a
__index.html__ file if above a certain threshold (see above).


IPv6
----

Since version > 0.91 __lophttpd__ also supports IPv6, by simply using `-6`
command-line switch. The default bind goes to `::` unless
given `-l` local bind address.
You can either run IPv4 or IPv6 in one instance, not both. But you can run
two lophttpd's: one with IPv4 and one with IPv6 if needed.
__Frontend__ reverse proxy also supports IPv6, both on the frontend and
the backend side. You can even mix IPv4 and IPv6 backend nodes.


Proxies
-------

If you operate _lophttpd_ behind a proxy, you can use the `-B string`
argument so it automatically generates <base href="string"> argument
which should be your proxy URL: http://proxy:port/path/.
The base string must end with '/' character and the index which lhttpd
generates is relative to this base. `-B` makes only sense with `-i`.


Special files
-------------

_lophttpd_ also serves block device files. You need to run it as
root (`-u root`) or as the user who can open the block dev files. This
is not really for production use, (keep the security implications in mind
if running as root) but its sometimes useful on embedded devices.

As well as device files, _lophttpd_ can serve __/proc__ or __/sys__ file systems.
!!! Be aware about the security consequences and that you sometimes will
get wrong results (proc/<pid> dirs come and go) !!!

Please note that serving __/proc__, __/sys__ and device files is a special
operation mode and not optimized for thousands of clients (although
its possible to do that) and that some of these files are blocking
so do not try to serve a block device that is a tape drive without a
tape or so. There is no web server which can do that, not even _lophttpd_.

If your web clients send a lot of requests to non existing files,
e.g. some buggy browsers always request /favicon.ico, no matter of
the base URL, you may consider using `-E` which does not close
the connection after non-fatal errors. That saves overhead of accepting
new connections and can matter if a lot of crippled requests are expected
from legit clients due to buggy browser/setups.


File upload
-----------

_Lophttpd_ supports file upload (via __PUT__ method) directly, w/o the need
for external CGI scripts or alike.

On the machine running _lophttpd_, you have to create a directory
named `upload` inside the web-root (and inside your vHost setup if any),
which must be owned by the user you run `lhttpd` as (e.g. 'wwwrun'). Then
start `lhttpd` like:

    # lhttpd -n 1 -i -U /upload

On client side:

    $ curl --upload-file /path/to/file http://lophttpd.host:port

Then, the file is transferred to `$WEBROOT/upload/file`. If you additionally
start `lhttpd` with `-r`, a random token is appended to the file when its stored.
If you put an empty __index.html__ inside __upload__, outside visitors cannot
download the uploaded file, as they do not know the URL. If you want that
nobody, not even the up-loader can see the URL, you can use `-Q`
This effectively creates you an upload-only service where you can store
submitted documents which nobody can download.


HTTPS
-----

Since version 0.98, _lophttpd_ supports HTTPS (TLSv1+). Just generate
a public/private keypair:

    $ openssl genrsa -out serverkey.pem 4096
    $ openssl req -new -x509 -nodes -sha1 -key serverkey.pem -out pubkey.x509

and append `-C pubkey.x509 -K serverkey.pem` to the _lophttpd_
commandline. You then either import the X509 certificate into your browser
or let it sign by some CA that is in your browsers CA chain.

As of the Snowden-leaks it became certain that the public CA infrastructure
is subverted and cannot be trusted if you need real security. So you
should setup your own CA (howto is beyond this README) or import
the generated X509 into your browser.
Additionally _lophttpd_ sets a cipher list that is believed to be
secure (no export ciphers, no weak ciphers and no ECC ciphers -
where most parameters are given by NIST).

If you also want ephemeral keying (known as Perfect Forward Secrecy [PFS])
you need to call the `newdh` script before you invoke `make`.
This will generate all the necessary DH parameters. Theres nothing more
to do on the `lhttpd` commandline then, PFS will be automatically used
if available.


If you have ideas and or offer performance/testing environment please
drop me an email: sebastian.krahmer [at] gmail [dot] com :-)

