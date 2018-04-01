include ../mk/net.mk

DIR=	${INITDIR}
SRCS=	bootmisc.in fsck.in hostname.in local.in localmount.in loopback.in \
	netmount.in osclock.in root.in savecache.in swap.in swclock.in \
	sysctl.in runsvdir.in urandom.in s6-svscan.in ${SRCS-${OS}}
BIN=	${OBJS}

# Are we installing our network scripts?
ifeq (${MKNET},yes)
SRCS+= network.in staticroute.in
endif

MK=	../mk
include ${MK}/os.mk

# Generic BSD scripts
SRCS-FreeBSD=	hostid.in modules.in moused.in newsyslog.in pf.in rarpd.in \
		rc-enabled.in rpcbind.in savecore.in syslogd.in
# These are FreeBSD specific
SRCS-FreeBSD+=	adjkerntz.in devd.in dumpon.in encswap.in ipfw.in \
		modules-load.in mixer.in nscd.in powerd.in syscons.in

SRCS-Linux=	agetty.in binfmt.in devfs.in cgroups.in dmesg.in hwclock.in \
	consolefont.in keymaps.in killprocs.in modules.in modules-load.in \
	mount-ro.in mtab.in numlock.in procfs.in net-online.in sysfs.in \
termencoding.in

# Generic BSD scripts
SRCS-NetBSD=	hostid.in moused.in newsyslog.in pf.in rarpd.in rc-enabled.in \
		rpcbind.in savecore.in syslogd.in
# These are NetBSD specific
SRCS-NetBSD+=	devdb.in swap-blk.in ttys.in wscons.in

include ${MK}/scripts.mk

_installafter_: realinstall
