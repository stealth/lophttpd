// testing TCP fast open
// cc tfo.c -std=c11 -pedantic -o tfo
// ./tfo 127.0.0.1
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>


void die(const char *msg)
{
	perror(msg);
	exit(errno);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		die("no IP given");

	int sfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sfd < 0)
		die("socket");
	struct sockaddr_in sin = {AF_INET, htons(80)};
	if (inet_pton(AF_INET, argv[1], &sin.sin_addr) != 1)
		die("inet_pton");
	if (sendto(sfd, "HEAD / HTTP/1.0\r\n\r\n", 19, MSG_FASTOPEN, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
		die("sendto");

	char buf[4096] = {0};
	ssize_t r = 0;
	if ((r = read(sfd, buf, sizeof(buf) - 1)) < 0)
		die("read");
	close(sfd);
	write(1, buf, r);
	return 0;
}

