#!/bin/sh
#
# gcov capability for udev
#
# Provides code coverage analysis for udev.
#
# make_gcov.sh assumes the same same default parameters as make, but also
# accepts the same parameters as make (see README file in udev/ for
# parameter info).  There is one exception, klibc can not be used with
# gcov as it will not compile cleanly.
#
# make_gcov.sh then overrides CFLAGS to strip out optimization in order
# for gcov to get correct code coverage analysis.
#
# Leann Ogasawara <ogasawara@osdl.org>, April 2004

# clean up udev dir
clean_udev () {
	find -name "*.gcno" -exec rm -f "{}" \;
	find -name "*.gcda" -exec rm -f "{}" \;
	find -name "*.gcov" -exec rm -f "{}" \;
	rm -f udev_gcov.txt
	make clean
}

PWD=`pwd`
GCCINCDIR=`gcc -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"`
LIBSYSFS="-I$PWD/libsysfs/sysfs -I$PWD/libsysfs"
WARNINGS="-Wall -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations"
GCC="-I$GCCINCDIR"
USE_LOG="-DLOG"
DEBUG="-D_GNU_SOURCE"
GCOV_FLAGS="-pipe -fprofile-arcs -ftest-coverage"

for i in $*; do
	pre=`echo $i | sed 's/=.*//g'`
	post=`echo $i | sed 's/.*=//g'`
	if [ $pre = "USE_KLIBC" ] && [ $post = "true" ]; then
		echo "cannot use gcov with klibc, will not compile"
		exit
	elif [ $pre = "USE_LOG" ] && [ $post = "false" ]; then
		USE_LOG=""
	elif [ $pre = "DEBUG" ] && [ $post = "true" ]; then
		DEBUG="-g -DDEBUG -D_GNU_SOURCE"
	elif [ $pre = "clean" ]; then
		clean_udev
		exit
	fi
done

clean_udev

make $* CFLAGS="$WARNINGS $GCOV_FLAGS $USE_LOG $DEBUG $GCC $LIBSYSFS" LDFLAGS="-Wl,-warn-common -fprofile-arcs"
