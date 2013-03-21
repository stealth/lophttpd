/* webstress webserver download bandwidth tesing tool
 * (C) 2011-2013 Sebastian Krahmer
 */
#include <iostream>
#include <map>
#include <string>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>



using namespace std;


enum {
	HTTP_STATE_CONNECTING = 0,
	HTTP_STATE_CONNECTED,
	HTTP_STATE_HANDSHAKING,
	HTTP_STATE_HANDSHAKED,
	HTTP_STATE_TRANSFERING
};


class webstress {

	string host, port, path, err;
	bool sequential, ssl;
	int max_cl, peers, ever, ests, success, hdr_fail, write_fail, read_fail, to_fail, hup_fail, max_fd;
	time_t now;

	pollfd *pfds;

	struct client {
		size_t obtained, content_length;
		int state;
		time_t time, start_time;
		SSL *ssl;
	};

	map<int, client *> clients;

	static const int TIMEOUT = 60;

	const SSL_METHOD *ssl_method;
	SSL_CTX *ssl_ctx;

public:
	webstress(const string &h, const string &p, const string &f, int max, bool seq = 0)
		: host(h), port(p), path(f), err(""), sequential(seq), ssl(0), max_cl(max),
		  peers(0), ever(0), ests(0), success(0), hdr_fail(0), write_fail(0), read_fail(0),
	          to_fail(0), hup_fail(0), max_fd(0), pfds(NULL)
	{
		if (p == "443")
			ssl = 1;

		ssl_method = NULL;
		ssl_ctx = NULL;
	}

	~webstress()
	{
	}

	void calc_max_fd();

	void max_clients(int n)
	{
		max_cl = n;
	}

	int ssl_init();

	int recv(int, char *, size_t, int);

	int loop();

	int cleanup(int);

	void print_stat(int);

	const char *why()
	{
		return err.c_str();
	}

};


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = write(fd, ptr+o, len)) <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return o;
			return n;
		}
		len -= n;
		o += n;
	}
	return o;
}


int webstress::recv(int fd, char *buf, size_t blen, int flags)
{
	int r = 0;

	if (ssl) {
		 if (!clients[fd]->ssl)
			return -1;

		if (flags == MSG_PEEK) {
			r = SSL_peek(clients[fd]->ssl, buf, blen);
			switch (SSL_get_error(clients[fd]->ssl, r)) {
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
				r = 0;
				break;
			default:
				r = -1;
			}
		} else {
			r = SSL_read(clients[fd]->ssl, buf, blen);
			switch (SSL_get_error(clients[fd]->ssl, r)) {
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_WANT_READ:
				r = 0;
				break;
			default:
				r = -1;
			}
		}

		return r;
	}

	return ::recv(fd, buf, blen, flags);
}


int webstress::cleanup(int fd)
{
	if (fd < 0)
		return -1;
	shutdown(fd, SHUT_RDWR);
	close(fd);
	pfds[fd].fd = -1;
	pfds[fd].events = pfds[fd].revents = 0;

	if (clients[fd]->state > HTTP_STATE_CONNECTING)
		--ests;

	if (ssl) {
		if (clients[fd]->ssl)
			SSL_free(clients[fd]->ssl);
	}

	delete clients[fd];
	clients[fd] = NULL;
	--peers;

	if (fd == max_fd)
		--max_fd;

	return 0;
}


void webstress::print_stat(int fd)
{
	if (now - clients[fd]->start_time == 0)
		--clients[fd]->start_time;

	char s = 'X';
	switch (clients[fd]->state) {
	case HTTP_STATE_CONNECTING:
		s = 'c';
		break;
	case HTTP_STATE_CONNECTED:
		s = 'C';
		break;
	case HTTP_STATE_TRANSFERING:
		s = 'T';
		break;
	case HTTP_STATE_HANDSHAKING:
		s = 'h';
		break;
	case HTTP_STATE_HANDSHAKED:
		s = 'H';
	}

	printf("(%c)[#=%08u][#S=%05u][#P=%05u][#EST=%05u][rf=%05u][hdrf=%05u][wf=%05u][tf=%05u][hf=%05u][cnt=%08u][%s][%f MB/s]\n",
	       s, ever, success, peers, ests,
	       read_fail, hdr_fail, write_fail, to_fail, hup_fail, clients[fd]->obtained,
	       path.c_str(),
	       (double)clients[fd]->content_length/(now - clients[fd]->start_time)/(1024*1024));
}

void webstress::calc_max_fd()
{
	for (int i = max_fd; i >= 0; --i) {
		if (pfds[i].fd != -1) {
			max_fd = i;
			return;
		}
	}
}


int webstress::ssl_init()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	if ((ssl_method = TLSv1_client_method()) == NULL) {
		fprintf(stderr, "ERR: TLSv1_client_method: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if ((ssl_ctx = SSL_CTX_new(ssl_method)) == NULL) {
		fprintf(stderr, "ERR: SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);
	return 0;
}


int webstress::loop()
{
	struct rlimit rl;

	if (geteuid() == 0) {
		rl.rlim_cur = (1<<16);
		rl.rlim_max = rl.rlim_cur;
		if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
			err = "webstress::loop::setrlimit:";
			err += strerror(errno);
			return -1;
		}
	} else {
		if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
			err = "webstress::loop::getrlimit:";
			err += strerror(errno);
			return -1;
		}
	}

	if (ssl) {
		if (ssl_init() < 0)
			return -1;
	}


	struct addrinfo *ai = NULL;
	int r = 0;
	if ((r = getaddrinfo(host.c_str(), port.c_str(), NULL, &ai)) < 0) {
		err = "webstress::loop::getaddrinfo:";
		err += gai_strerror(r);
		return -1;
	}

	pfds = new (nothrow) pollfd[rl.rlim_cur];
	if (!pfds) {
		err = "webstress::loop::OOM";
		return -1;
	}

	for (unsigned int i = 0; i < rl.rlim_cur; ++i)
		pfds[i].fd = -1;

	char GET[1024], buf[4096];

	snprintf(GET, sizeof(GET), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path.c_str(),
	         host.c_str());
	size_t GET_len = strlen(GET);

	int sock = 0, one = 1;
	for (;;) {
		now = time(NULL);
		while (peers + 10 < max_cl) {
			if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
				err = "webstress::loop::socket:";
				err += strerror(errno);
				return -1;
			}
			fcntl(sock, F_SETFL, O_RDWR|O_NONBLOCK);
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
			if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 &&
			    errno != EINPROGRESS) {
				err = "webstress::loop::connect:";
				err += strerror(errno);
				printf("%s\n", err.c_str());
				break;
			}
			client *c = new client;
			memset(c, 0, sizeof(client));
			c->state = HTTP_STATE_CONNECTING;
			c->time = now;
			clients[sock] = c;

			pfds[sock].fd = sock;
			pfds[sock].events = POLLIN|POLLOUT;
			pfds[sock].revents = 0;
			++peers; ++ever;
			if (sock > max_fd)
				max_fd = sock;
		}

		if (poll(pfds, max_fd + 1, 10000) < 0)
			continue;

		// starts at most at FD 3
		for (int i = 3; i <= max_fd ; ++i) {
			now = time(NULL);

			if (!clients[i])
				continue;
			if (pfds[i].revents == 0 && now - clients[i]->time > TIMEOUT) {
				++to_fail;
				print_stat(i);
				cleanup(i);
				continue;
			}
			if (pfds[i].revents == 0)
				continue;

			if ((pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) != 0) {
				++hup_fail;
				print_stat(i);
				cleanup(i);
				continue;
			}

			if (clients[i]->state == HTTP_STATE_CONNECTING) {
				int e = 0;
				socklen_t elen = sizeof(e);
				if (getsockopt(i, SOL_SOCKET, SO_ERROR, &e, &elen) < 0) {
					cleanup(i);
					continue;
				}
				if (e != 0) {
					++hup_fail;
					print_stat(i);
					cleanup(i);
					continue;
				}
				++ests;

				if (ssl) {
					clients[i]->state = HTTP_STATE_HANDSHAKING;
					clients[i]->ssl = SSL_new(ssl_ctx);
					SSL_set_fd(clients[i]->ssl, i);
					pfds[i].events = POLLOUT;
				} else {
					clients[i]->state = HTTP_STATE_CONNECTED;

					if (writen(i, GET, GET_len) <= 0) {
						++write_fail;
						print_stat(i);
						cleanup(i);
						continue;
					}

					pfds[i].events = POLLIN;
				}

				pfds[i].revents = 0;
				clients[i]->start_time = clients[i]->time = now;

			} else if (clients[i]->state == HTTP_STATE_HANDSHAKING) {
				r = SSL_connect(clients[i]->ssl);
				switch (SSL_get_error(clients[i]->ssl, r)) {
				case SSL_ERROR_NONE:
					clients[i]->state = HTTP_STATE_HANDSHAKED;
					pfds[i].events = POLLOUT;
					clients[i]->time = now;
					break;
				case SSL_ERROR_WANT_READ:
					pfds[i].events = POLLIN;
					break;
				default:
					print_stat(i);
					cleanup(i);
				}
				pfds[i].revents = 0;

			} else if (clients[i]->state == HTTP_STATE_HANDSHAKED) {
				r = SSL_write(clients[i]->ssl, GET, GET_len);
				switch (SSL_get_error(clients[i]->ssl, r)) {
				case SSL_ERROR_NONE:
					clients[i]->state = HTTP_STATE_CONNECTED;
					pfds[i].events = POLLIN;
					clients[i]->time = now;
					break;
				case SSL_ERROR_WANT_WRITE:
					pfds[i].events = POLLOUT;
					break;
				default:
					print_stat(i);
					cleanup(i);
				}
				pfds[i].revents = 0;

			// just read header and extract Content-Length if found
			} else if (clients[i]->state == HTTP_STATE_CONNECTED) {
				memset(buf, 0, sizeof(buf));
				r = this->recv(i, buf, sizeof(buf) - 1, MSG_PEEK);

				if (ssl && r == 0)
					continue;

				if (r <= 0) {
					++read_fail;
					print_stat(i);
					cleanup(i);
					continue;
				}

				char *ptr = NULL;
				if ((ptr = strstr(buf, "\r\n\r\n")) == NULL) {
					if (now - clients[i]->time > TIMEOUT) {
						++to_fail;
						print_stat(i);
						cleanup(i);
					}
					continue;
				}
				if (this->recv(i, buf, ptr - buf + 4, 0) <= 0) {
					++hdr_fail;
					cleanup(i);
					continue;
				}
				clients[i]->state = HTTP_STATE_TRANSFERING;
				clients[i]->time = now;

				char *end_ptr = buf + (ptr - buf + 4);
				if ((ptr = strcasestr(buf, "Content-Length:")) != NULL) {
					ptr += 15;
					for (;ptr < end_ptr; ++ptr) {
						if (*ptr != ' ')
							break;
					}
					if (ptr >= end_ptr) {
						cleanup(i);
						continue;
					}
					clients[i]->content_length = strtoul(ptr, NULL, 10);
				} else
					clients[i]->content_length = (size_t)-1;

				clients[i]->obtained = 0;
				pfds[i].revents = 0;
				pfds[i].events = POLLIN;

			// read content
			} else if (clients[i]->state == HTTP_STATE_TRANSFERING) {
				errno = 0;
				r = this->recv(i, buf, sizeof(buf), 0);

				if (ssl && r == 0)
					continue;

				if (r <= 0) {
					++read_fail;
					cleanup(i);
					continue;
				}

				clients[i]->obtained += r;
				if (clients[i]->obtained == clients[i]->content_length || r == 0) {
					if (clients[i]->obtained == clients[i]->content_length)
						++success;
					else
						++to_fail;
					print_stat(i);
					cleanup(i);
					continue;
				}
				pfds[i].revents = 0;
				pfds[i].events = POLLIN;
				clients[i]->time = now;
			} else {
				cleanup(i);
			}
		}
		calc_max_fd();

	}
	return 0;
}


int main(int argc, char **argv)
{

	if (argc < 5) {
		cerr<<"Usage: ws <host> <port> <path> <#clients>\n";
		return 1;
	}

	if (atoi(argv[4]) < 20) {
		cerr<<"Minimum of 20 clients";
		return 1;
	}
	webstress ws(argv[1], argv[2], argv[3], atoi(argv[4]), 0);

	if (ws.loop() < 0)
		cerr<<ws.why()<<endl;

	return 1;
}

