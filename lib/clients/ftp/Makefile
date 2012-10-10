top_builddir=/Users/tj/proftpd/cvs/proftpd
top_srcdir=/Users/tj/proftpd/cvs/proftpd
srcdir=.

include $(top_srcdir)/Make.rules

.SUFFIXES: .la .lo

CLIENT_NAME=ftp

CLIENT_DEPS=\
  $(top_srcdir)/src/pool.o \
  $(top_srcdir)/src/sets.o \
  $(top_srcdir)/src/table.o \
  $(top_srcdir)/src/str.o \
  $(top_srcdir)/src/event.o \
  $(top_srcdir)/src/parser.o \
  $(top_srcdir)/src/expr.o \
  $(top_srcdir)/src/netacl.o \
  $(top_srcdir)/src/netaddr.o \
  $(top_srcdir)/src/netio.o \
  $(top_srcdir)/src/inet.o \
  $(top_srcdir)/src/fsio.o \
  $(top_srcdir)/src/log.o \
  $(top_srcdir)/src/auth.o \
  $(top_srcdir)/src/wtmp.o \
  $(top_srcdir)/src/privs.o \
  $(top_srcdir)/src/var.o \
  $(top_srcdir)/src/env.o \
  $(top_srcdir)/src/timers.o \
  $(top_srcdir)/src/session.o \
  $(top_srcdir)/src/scoreboard.o \
  $(top_srcdir)/src/proctitle.o \
  $(top_srcdir)/src/display.o \
  $(top_srcdir)/src/dirtree.o \
  $(top_srcdir)/src/support.o \
  $(top_srcdir)/src/regexp.o \
  $(top_srcdir)/src/class.o \
  $(top_srcdir)/src/cmd.o \
  $(top_srcdir)/src/data.o \
  $(top_srcdir)/src/response.o \
  $(top_srcdir)/src/stash.o \
  $(top_srcdir)/src/modules.o \
  $(top_srcdir)/src/ctrls.o \
  $(top_srcdir)/src/trace.o

CLIENT_OBJS=ftp.o stubs.o
BLOCKING_CLIENT_OBJS=ftp-blocking.o stubs.o

# Necessary redefinitions
INCLUDES=-I. -I../.. -I$(top_srcdir) -I$(top_srcdir)/include
CPPFLAGS= $(ADDL_CPPFLAGS) -DHAVE_CONFIG_H $(DEFAULT_PATHS) $(PLATFORM) $(INCLUDES)
LDFLAGS=-L$(top_srcdir)/lib

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

check: $(CLIENT_OBJS) $(BLOCKING_CLIENT_OBJS)
	$(LIBTOOL) --mode=link --tag=CC $(CC) $(LDFLAGS) -o ftp $(CLIENT_DEPS) $(CLIENT_OBJS) $(LIBS)
	$(LIBTOOL) --mode=link --tag=CC $(CC) $(LDFLAGS) -o ftp-blocking $(CLIENT_DEPS) $(BLOCKING_CLIENT_OBJS) $(LIBS)

clean:
	$(RM) $(CLIENT_NAME) $(CLIENT_NAME).a *.o *.la *.lo
	$(LIBTOOL) --mode=clean $(RM) "$(CLIENT_NAME).o"
	$(LIBTOOL) --mode=clean $(RM) `echo "$(CLIENT_NAME).la" | sed 's/\.la$\/.lo/g'`
