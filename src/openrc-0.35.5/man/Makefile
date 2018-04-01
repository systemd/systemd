MK=		../mk
include ${MK}/sys.mk
include ${MK}/os.mk

MAN3=		einfo.3 \
		rc_config.3 rc_deptree.3 rc_find_pids.3 rc_plugin_hook.3 \
		rc_runlevel.3 rc_service.3 rc_stringlist.3
MAN8=		rc-service.8 rc-status.8 rc-update.8 openrc.8 openrc-run.8 \
		start-stop-daemon.8 supervise-daemon.8

ifeq (${OS},Linux)
MAN8 += rc-sstat.8 openrc-init.8 openrc-shutdown.8
endif

# Handy macro to create symlinks
# This does rely on correctly formatting our manpages!
MAKE_LINKS=	suffix=$${man\#*.}; \
		prefix=$${man%%.*}; \
		for link in `sed -e 's/ ,//g' \
		-n -e '/^\.Sh NAME$$/,/\.Sh/ s/\.Nm //p' $${man}`; do \
		if test "$${link}" != "$${prefix}" ; then \
		ln -sf $${man} \
		${DESTDIR}/${MANDIR}/man$${suffix}/$${link}.$${suffix} ; \
		fi; \
		done;

include ${MK}/gitignore.mk

all:

install:
	${INSTALL} -d ${DESTDIR}/${MANDIR}/man3
	for man in ${MAN3}; do \
		${INSTALL} -m ${MANMODE} "$$man" ${DESTDIR}/${MANDIR}/man3 || exit $$?; \
		${MAKE_LINKS} \
	done
	${INSTALL} -d ${DESTDIR}/${MANDIR}/man8
	for man in ${MAN8}; do \
		${INSTALL} -m ${MANMODE} "$$man" ${DESTDIR}/${MANDIR}/man8 || exit $$?; \
		${MAKE_LINKS} \
	done

check test::

clean:
