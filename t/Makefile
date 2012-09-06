CC=gcc
LIBTOOL=libtool

proftpd_dir=/home/tj/proftpd/cvs/proftpd
top_srcdir=..

EXEEXT=

CPPFLAGS=-I. -I.. -I$(proftpd_dir) -I$(proftpd_dir)/include
CFLAGS=-DLINUX
LDFLAGS=-L$(proftpd_dir)/lib
LIBS=-lsupp

TEST_API_DEPS=\
  $(proftpd_dir)/src/pool.o \
  $(proftpd_dir)/src/str.o \
  $(top_srcdir)/uri.o

TEST_API_LIBS=-lcheck

TEST_API_OBJS=\
  api/uri.o \
  api/stubs.o \
  api/tests.o

dummy:

api/.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

api-tests$(EXEEXT): $(TEST_API_OBJS) $(TEST_API_DEPS)
	$(LIBTOOL) --mode=link --tag=CC $(CC) $(LDFLAGS) -o $@ $(TEST_API_DEPS) $(TEST_API_OBJS) $(LIBS) $(TEST_API_LIBS)
	./$@

clean:
	$(LIBTOOL) --mode=clean $(RM) *.o api/*.o api-tests$(EXEEXT) api-tests.log

