include ../../Makefile.inc
MK=		../../mk
include ${MK}/os.mk

SRCS=	checkpath.c do_e.c do_mark_service.c do_service.c \
		do_value.c fstabinfo.c is_newer_than.c is_older_than.c \
		mountinfo.c openrc-run.c rc-abort.c rc.c \
		rc-depend.c rc-logger.c rc-misc.c rc-plugin.c \
		rc-service.c rc-status.c rc-update.c \
		shell_var.c start-stop-daemon.c supervise-daemon.c swclock.c _usage.c

ifeq (${MKSELINUX},yes)
SRCS+=		rc-selinux.c
endif

ifeq (${OS},Linux)
SRCS+=		kill_all.c openrc-init.c openrc-shutdown.c rc-wtmp.c
endif

CLEANFILES=	version.h rc-selinux.o

BINDIR=		${PREFIX}/bin
SBINDIR=	${PREFIX}/sbin
LINKDIR=	${LIBEXECDIR}

BINPROGS=	rc-status
SBINPROGS = openrc openrc-run rc rc-service rc-update runscript \
			start-stop-daemon supervise-daemon
RC_BINPROGS=	einfon einfo ewarnn ewarn eerrorn eerror ebegin eend ewend \
				eindent eoutdent esyslog eval_ecolors ewaitfile \
				veinfo vewarn vebegin veend vewend veindent veoutdent \
				checkpath fstabinfo mountinfo rc-depend \
				is_newer_than is_older_than \
				service_get_value service_set_value get_options save_options \
				service_starting service_started \
				service_stopping service_stopped \
				service_inactive service_wasinactive \
				service_hotplugged service_started_daemon service_crashed \
				shell_var
RC_SBINPROGS=	mark_service_starting mark_service_started \
		mark_service_stopping mark_service_stopped \
		mark_service_inactive mark_service_wasinactive \
		mark_service_hotplugged mark_service_failed \
		rc-abort swclock

ifeq (${OS},Linux)
RC_BINPROGS+= kill_all
SBINPROGS+= openrc-init openrc-shutdown
endif

ALL_PROGS=	${BINPROGS} ${SBINPROGS} ${RC_BINPROGS} ${RC_SBINPROGS}
CLEANFILES+=	${ALL_PROGS}

LOCAL_CPPFLAGS=-I../includes -I../librc -I../libeinfo
LOCAL_LDFLAGS=-L../librc -L../libeinfo
LDADD+=		-lutil -lrc -leinfo

include ${MK}/prog.mk
include ${MK}/gitver.mk
include ${MK}/cc.mk

include ${MK}/termcap.mk
LDADD+=		${LIBDL} ${LIBKVM}
include ${MK}/pam.mk

${SRCS}: version.h

.PHONY:	version.h.tmp
version.h.tmp:
	echo "#define VERSION \"${VERSION}${GITVER}\"" >$@
	if test -n "${BRANDING}"; then \
		echo "#define BRANDING \"${BRANDING}\"" >> $@; \
	fi

version.h: version.h.tmp
	cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

install: all
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${BINMODE} ${SBINPROGS} ${DESTDIR}${SBINDIR}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -m ${BINMODE} ${BINPROGS} ${DESTDIR}${BINDIR}
	${INSTALL} -d ${DESTDIR}${LINKDIR}/bin
	${INSTALL} -m ${BINMODE} ${RC_BINPROGS} ${DESTDIR}${LINKDIR}/bin
	${INSTALL} -d ${DESTDIR}${LINKDIR}/sbin
	${INSTALL} -m ${BINMODE} ${RC_SBINPROGS} ${DESTDIR}${LINKDIR}/sbin
	if test "${MKPAM}" = pam; then \
		${INSTALL} -d ${DESTDIR}${PAMDIR}; \
		${INSTALL} -m ${PAMMODE} start-stop-daemon.pam ${DESTDIR}${PAMDIR}/start-stop-daemon; \
		${INSTALL} -m ${PAMMODE} supervise-daemon.pam ${DESTDIR}${PAMDIR}/supervise-daemon; \
	fi

check test::

all: ${ALL_PROGS}

checkpath: checkpath.o _usage.o rc-misc.o
ifeq (${MKSELINUX},yes)
checkpath: rc-selinux.o
endif
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

kill_all: kill_all.o _usage.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

einfon einfo ewarnn ewarn eerrorn eerror ebegin eend ewend \
eindent eoutdent esyslog eval_ecolors ewaitfile \
veinfo vewarn vebegin veend vewend veindent veoutdent: do_e.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

fstabinfo: fstabinfo.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

openrc-init: openrc-init.o rc-wtmp.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

is_newer_than: is_newer_than.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

is_older_than: is_older_than.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

mark_service_starting mark_service_started \
mark_service_stopping mark_service_stopped \
mark_service_inactive mark_service_wasinactive \
mark_service_hotplugged mark_service_failed: do_mark_service.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

mountinfo: mountinfo.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

openrc rc: rc.o rc-logger.o rc-misc.o rc-plugin.o _usage.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

openrc-shutdown: openrc-shutdown.o _usage.o rc-wtmp.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

openrc-run runscript: openrc-run.o _usage.o rc-misc.o rc-plugin.o
ifeq (${MKSELINUX},yes)
openrc-run runscript: rc-selinux.o
endif
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

rc-abort: rc-abort.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ -leinfo

rc-depend: rc-depend.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

rc-status: rc-status.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

rc-service: rc-service.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

rc-update: rc-update.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

start-stop-daemon: start-stop-daemon.o _usage.o rc-misc.o rc-schedules.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

supervise-daemon: supervise-daemon.o _usage.o rc-misc.o rc-schedules.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

service_get_value service_set_value get_options save_options: do_value.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

service_starting service_started \
service_stopping service_stopped \
service_inactive service_wasinactive \
service_hotplugged service_started_daemon \
service_crashed: do_service.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}

shell_var: shell_var.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^

swclock: swclock.o _usage.o rc-misc.o
	${CC} ${LOCAL_CFLAGS} ${LOCAL_LDFLAGS} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${LDADD}
