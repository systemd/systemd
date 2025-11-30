/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <getopt.h>

/* musl's getopt_long() behaves something different in handling optional arguments.
 * ========
 * $ journalctl _PID=1 _COMM=systemd --since 19:19:01 -n all --follow
 * Failed to add match 'all': Invalid argument
 * ========
 * This happens when an unmatching option appears before an option that takes an optional argument. So, the
 * following works as expected:
 * ========
 * $ journalctl --since 19:19:01 -n all --follow _PID=1 _COMM=systemd
 * ========
 * Here, we introduce getopt_long_reorder() that reorders the passed arguments to make getopt_long() provided
 * by musl works as what we expect. */
int getopt_long_reorder(
                int argc,
                char * const *argv,
                const char *optstring,
                const struct option *longopts,
                int *longindex);

#define getopt_long(argc, argv, optstring, longopts, longindex)         \
        getopt_long_reorder(argc, argv, optstring, longopts, longindex)

/* musl's getopt() always behaves POSIXLY_CORRECT mode, and stops parsing when a non-option string found.
 * Let's always use getopt_long(). */
#define getopt(argc, argv, optstring)                                   \
        getopt_long_reorder(argc, argv, optstring, NULL, NULL)
