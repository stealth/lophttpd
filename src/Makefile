
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

all:
	make -f $(MAKEFILE)

