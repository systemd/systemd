#!/bin/sh

#
# run gcov on udev
#
# Generate code coverage analysis for udev files
#
# This requires that you compiled udev with gcov flags i.e.
# you should have compiled udev with the make_gcov.sh script.
#
# Leann Ogasawara <ogasawara@osdl.org>, April 2004

PWD=`pwd`

# check if root else may not have access to *.da files
# and gcov analysis will fail.
if [ $(id -u) -ne 0 ]; then
	echo "please become root before executing run_gcov.sh"
	exit 1
fi

echo > udev_gcov.txt
echo "CODE COVERAGE ANALYSIS FOR UDEV" >> udev_gcov.txt
echo  >> udev_gcov.txt

for file in `find -maxdepth 1 -name "*.gcno"`; do
	name=`basename $file .gcno`
	echo "################" >> udev_gcov.txt
	echo "$name.c" >> udev_gcov.txt
	echo "################" >> udev_gcov.txt
	if [ -e "$name.gcda" ]; then
		gcov -l "$name.c" >> udev_gcov.txt 2>&1
	else
		echo "code for $name.c was never executed" >> udev_gcov.txt 2>&1
		echo "no code coverage analysis to be done" >> udev_gcov.txt 2>&1
	fi
	echo >> udev_gcov.txt
done

echo "udev gcov analysis done.  View udev_gcov.txt for results."
