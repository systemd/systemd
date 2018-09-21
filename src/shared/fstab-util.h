/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "macro.h"

int fstab_is_mount_point(const char *mount);
int fstab_has_fstype(const char *fstype);

int fstab_filter_options(const char *opts, const char *names, const char **namefound, char **value, char **filtered);

int fstab_extract_values(const char *opts, const char *name, char ***values);

static inline bool fstab_test_option(const char *opts, const char *names) {
        return !!fstab_filter_options(opts, names, NULL, NULL, NULL);
}

int fstab_find_pri(const char *options, int *ret);

static inline bool fstab_test_yes_no_option(const char *opts, const char *yes_no) {
        int r;
        const char *opt;

        /* If first name given is last, return 1.
         * If second name given is last or neither is found, return 0. */

        r = fstab_filter_options(opts, yes_no, &opt, NULL, NULL);
        assert(r >= 0);

        return opt == yes_no;
}

char *fstab_node_to_udev_node(const char *p);
