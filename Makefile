CXX=c++ -Wall -O2 -DGETFL_OPTIMIZATION
LD=c++

all: lhttpd frontend

clean:
	rm -f *.o

distclean: clean
	rm -f lhttpd

lhttpd: lonely.o socket.o main.o misc.o log.o multicore.o config.o
	$(LD) lonely.o socket.o main.o misc.o log.o multicore.o config.o -o lhttpd -lrt


frontend: lonely.o socket.o frontend-main.o log.o multicore.o rproxy.o config.o misc.o
	$(LD) lonely.o socket.o frontend-main.o misc.o log.o multicore.o rproxy.o config.o -o frontend -lrt

frontend-main.o: frontend-main.cc
	$(CXX) -c frontend-main.cc

rproxy.o: rproxy.cc rproxy.h
	$(CXX) -c rproxy.cc

config.o: config.cc config.h
	$(CXX) -c config.cc

multicore.o: multicore.cc multicore.h
	$(CXX) -c multicore.cc

log.o: log.cc log.h
	$(CXX) -c log.cc

misc.o: misc.cc misc.h
	$(CXX) -c misc.cc

main.o: main.cc
	$(CXX) -c main.cc

socket.o: socket.cc socket.h
	$(CXX) -c socket.cc

lonely.o: lonely.cc lonely.h
	$(CXX) -c lonely.cc

