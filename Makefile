#
# This is the Makefile for the Linux flavor
#

# comment out if you dont need SSL/TLS

DEFS=-DUSE_SSL
LIBS=-lssl -lcrypto

# comment in for libressl and adjust to your path
# remember to put libressl lib path to /etc/ld.so.config or LD_LIBRARY_PATH
#DEFS+=-I/opt/libressl/include
#LIBS+=-L/opt/libressl/lib64

# enable Linux seccomp sandboxing
#DEFS+=-DUSE_SANDBOX

#override lophttps secure cipher list
#DEFS+=-DUSE_CIPHERS=\"ALL:!ADH:!LOW:!EXP:!RC4:!MD5:kDHE:@STRENGTH\"

CXX=c++ -Wall -O2 $(DEFS) -ansi
LD=c++

all: lhttpd frontend

clean:
	rm -f *.o

distclean: clean
	rm -f lhttpd

lhttpd: lonely.o socket.o main.o misc.o log.o multicore.o config.o flavor.o client.o dh.o ssl.o
	$(LD) $(LDFLAGS) lonely.o socket.o main.o misc.o log.o multicore.o config.o flavor.o\
	                 client.o dh.o ssl.o -o lhttpd $(LIBS)


frontend: lonely.o socket.o frontend-main.o log.o multicore.o rproxy.o config.o misc.o flavor.o client.o dh.o ssl.o
	$(LD) $(LDFLAGS) lonely.o socket.o frontend-main.o misc.o log.o multicore.o rproxy.o\
	                 config.o flavor.o client.o dh.o ssl.o -o frontend $(LIBS)

frontend-main.o: frontend-main.cc
	$(CXX) $(CFLAGS) -c frontend-main.cc

rproxy.o: rproxy.cc rproxy.h
	$(CXX) $(CFLAGS) -c rproxy.cc

config.o: config.cc config.h
	$(CXX) $(CFLAGS) -c config.cc

multicore.o: multicore.cc multicore.h
	$(CXX) $(CFLAGS) -c multicore.cc

log.o: log.cc log.h
	$(CXX) $(CFLAGS) -c log.cc

misc.o: misc.cc misc.h
	$(CXX) $(CFLAGS) -c misc.cc

main.o: main.cc
	$(CXX) $(CFLAGS) -c main.cc

flavor.o: flavor-linux.cc flavor.h
	$(CXX) $(CFLAGS) -c flavor-linux.cc -o flavor.o

socket.o: socket.cc socket.h
	$(CXX) $(CFLAGS) -c socket.cc

lonely.o: lonely.cc lonely.h
	$(CXX) $(CFLAGS) -c lonely.cc

client.o: client.cc client.h
	$(CXX) $(CFLAGS) -c client.cc

dh.o: dh.cc dh2048.cc
	$(CXX) $(CFLAGS) -c dh.cc

ssl.o: ssl.cc ssl.h
	$(CXX) $(CFLAGS) -c ssl.cc


