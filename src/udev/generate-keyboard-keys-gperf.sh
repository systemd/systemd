#!/bin/sh
set -eu

awk '
    BEGIN {
        print "%{\n\
#if __GNUC__ >= 7\n\
_Pragma(\"GCC diagnostic ignored \\\"-Wimplicit-fallthrough\\\"\")\n\
#endif\n\
%}"
        print "struct key_name { const char* name; unsigned short id; };"
        print "%null-strings"
        print "%%"
    }

    /^KEY_/ { print tolower(substr($1 ,5)) ", " $1 }
    { print tolower($1) ", " $1 }
' < "$1"
