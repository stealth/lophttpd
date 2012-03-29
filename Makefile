#
# This is the Makefile for the Linux flavor
#

CXX=c++ -Wall -O2
LD=c++

all: lhttpd frontend

clean:
	rm -f *.o

distclean: clean
	rm -f lhttpd

lhttpd: lonely.o socket.o main.o misc.o log.o multicore.o config.o flavor.o
	$(LD) $(LDFLAGS) lonely.o socket.o main.o misc.o log.o multicore.o config.o flavor.o -o lhttpd -lrt


frontend: lonely.o socket.o frontend-main.o log.o multicore.o rproxy.o config.o misc.o flavor.o
	$(LD) $(LDFLAGS) lonely.o socket.o frontend-main.o misc.o log.o multicore.o rproxy.o config.o flavor.o -o frontend -lrt

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

