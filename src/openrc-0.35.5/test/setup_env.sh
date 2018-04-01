#!/bin/sh

if [ -z "${top_srcdir}" ] ; then
	echo "You must set top_srcdir before sourcing this file" 1>&2
	exit 1
fi

srcdir=${srcdir:-.}
top_builddir=${top_builddir:-${top_srcdir}}
builddir=${builddir:-${srcdir}}

LD_LIBRARY_PATH=${top_builddir}/src/libeinfo:${top_builddir}/src/librc:${LD_LIBRARY_PATH}
PATH=${top_builddir}/src/rc:${PATH}
export LD_LIBRARY_PATH PATH

if [ ! -f ${top_srcdir}/sh/functions.sh ] ; then
	echo "functions.sh not yet created !?" 1>&2
	exit 1
elif ! . ${top_srcdir}/sh/functions.sh; then
	echo "Sourcing functions.sh failed !?" 1>&2
	exit 1
fi

