#!/bin/sh -e
echo $1 | sed -e 's#^dvb\([0-9]\)\.\([^0-9]*\)\([0-9]\)#dvb/adapter\1/\2\3#'
exit 0
