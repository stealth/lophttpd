CXX=c++ -Wall -O2 -DGETFL_OPTIMIZATION -DSTAT_CACHE
LD=c++

all: lhttpd

clean:
	rm -f *.o

distclean: clean
	rm -f lhttpd

lhttpd: lonely.o socket.o main.o misc.o log.o multicore.o
	$(LD) lonely.o socket.o main.o misc.o log.o multicore.o -o lhttpd -lrt

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

