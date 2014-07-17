include ../../Makefile.config

OBJS= asn1.o config.o pkixip_ext.o pkixip_ext_gram.o pkixip_ext_lex.o \
	util.o ver.o x509.o vers
LIB= pkixipext
VERSION= 1
TESTS= test
RUNTESTS= test

LDLIBS= -lcrypto -llog

YFLAGS= -d -p pkixip_ext_
LFLAGS= -Ppkixip_ext_
EXTRACLEAN= y.tab.h

include ../Makefile.lib.common
