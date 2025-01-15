#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

# shellcheck disable=SC1004
awk '
    BEGIN {
        print "%{\n\
_Pragma(\"GCC diagnostic ignored \\\"-Wimplicit-fallthrough\\\"\")\n\
#if __GNUC__ >= 15\n\
_Pragma(\"GCC diagnostic ignored \\\"-Wzero-as-null-pointer-constant\\\"\")\n\
#endif\n\
%}"
        print "struct key_name { const char* name; unsigned short id; };"
        print "%null-strings"
        print "%%"
    }

    /^KEY_/ { print tolower(substr($1 ,5)) ", " $1 }
    { print tolower($1) ", " $1 }
' <"${1:?}"
