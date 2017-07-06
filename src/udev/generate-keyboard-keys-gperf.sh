#!/bin/sh -eu
awk '   BEGIN {
                print "struct key_name { const char* name; unsigned short id; };"
                print "%null-strings"
                print "%%"
        }

        /^KEY_/ { print tolower(substr($1 ,5)) ", " $1 }
                { print tolower($1) ", " $1 }
' < "$1"
