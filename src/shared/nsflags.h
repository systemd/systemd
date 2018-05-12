/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#include <sched.h>

#include "missing.h"

/* The combination of all namespace flags defined by the kernel. The right type for this isn't clear. setns() and
 * unshare() expect these flags to be passed as (signed) "int", while clone() wants them as "unsigned long". The latter
 * is definitely more appropriate for a flags parameter, and also the larger type of the two, hence let's stick to that
 * here. */
#define NAMESPACE_FLAGS_ALL                                             \
        ((unsigned long) (CLONE_NEWCGROUP|                              \
                          CLONE_NEWIPC|                                 \
                          CLONE_NEWNET|                                 \
                          CLONE_NEWNS|                                  \
                          CLONE_NEWPID|                                 \
                          CLONE_NEWUSER|                                \
                          CLONE_NEWUTS))

const char* namespace_flag_to_string(unsigned long flag);
unsigned long namespace_flag_from_string(const char *name);
int namespace_flag_from_string_many(const char *name, unsigned long *ret);
int namespace_flag_to_string_many(unsigned long flags, char **ret);

static inline int namespace_flag_to_string_many_with_check(unsigned long n, char **s) {
        if ((n & NAMESPACE_FLAGS_ALL) != n)
                return -EINVAL;

        return namespace_flag_to_string_many(n, s);
}

struct namespace_flag_map {
        unsigned long flag;
        const char *name;
};

extern const struct namespace_flag_map namespace_flag_map[];
