MAKEFILE=Makefile.linux

ifeq ($(shell uname -o), GNU/Linux)
	MAKEFILE=Makefile.linux
else ifeq ($(shell uname -o), FreeBSD)
	MAKEFILE=Makefile.bsd
else ifeq ($(shell uname -o), NetBSD)
	MAKEFILE=Makefile.bsd
else ifeq ($(shell uname -o), OpenBSD)
	MAKEFILE=Makefile.bsd
else ifeq ($(shell uname -o), Darwin)
	MAKEFILE=Makefile.osx
endif

.PHONY: all clean buildclean

all:
	make -f $(MAKEFILE)

clean:
	make -f $(MAKEFILE) clean

buildclean:
	make -f $(MAKEFILE) buildclean

