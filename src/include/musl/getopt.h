/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* getopt() is provided both in getopt.h and unistd.h. Hence, we need to tentatively undefine it. */
#undef getopt

#include_next <getopt.h>

/* musl's getopt() always behaves POSIXLY_CORRECT mode, and stops parsing arguments when a non-option string
 * found. Let's always use getopt_long(). */
int getopt_fix(int argc, char * const *argv, const char *optstring);
#define getopt(argc, argv, optstring) getopt_fix(argc, argv, optstring)

/* musl's getopt_long() behaves something different in handling optional arguments.
 * ========
 * $ journalctl _PID=1 _COMM=systemd --since 19:19:01 -n all --follow
 * Failed to add match 'all': Invalid argument
 * ========
 * Here, we introduce getopt_long_fix() that reorders the passed arguments to make getopt_long() provided by
 * musl works as what we expect. */
int getopt_long_fix(
                int argc,
                char * const *argv,
                const char *optstring,
                const struct option *longopts,
                int *longindex);

#define getopt_long(argc, argv, optstring, longopts, longindex)         \
        getopt_long_fix(argc, argv, optstring, longopts, longindex)
