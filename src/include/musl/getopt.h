/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* getopt() is provided both in getopt.h and unistd.h. Hence, we need to tentatively undefine it. */
#undef getopt

#include_next <getopt.h>

#include "getopt_def.h"

#define getopt_long(argc, argv, optstring, longopts, longindex)         \
        getopt_long_reorder(argc, argv, optstring, longopts, longindex)
