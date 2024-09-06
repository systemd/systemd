/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "macro.h"

bool fstab_enabled_full(int enabled);
static inline bool fstab_enabled(void) {
        return fstab_enabled_full(-1);
}
static inline bool fstab_set_enabled(bool enabled) {
        return fstab_enabled_full(enabled);
}

bool fstab_is_extrinsic(const char *mount, const char *opts);
int fstab_has_fstype(const char *fstype);

int fstab_is_mount_point_full(const char *where, const char *path);
static inline int fstab_is_mount_point(const char *where) {
        return fstab_is_mount_point_full(where, NULL);
}
static inline int fstab_has_node(const char *path) {
        return fstab_is_mount_point_full(NULL, path);
}

int fstab_has_mount_point_prefix_strv(char **prefixes);

int fstab_filter_options(
                const char *opts,
                const char *names,
                const char **ret_namefound,
                char **ret_value,
                char ***ret_values,
                char **ret_filtered);
static inline bool fstab_test_option(const char *opts, const char *names) {
        return fstab_filter_options(opts, names, NULL, NULL, NULL, NULL);
}
static inline bool fstab_test_yes_no_option(const char *opts, const char *yes_no) {
        const char *opt_found;

        /* If first name given is last, return 1.
         * If second name given is last or neither is found, return 0. */

        assert_se(fstab_filter_options(opts, yes_no, &opt_found, NULL, NULL, NULL) >= 0);

        return opt_found == yes_no;
}
int fstab_find_pri(const char *opts, int *ret);

char* fstab_node_to_udev_node(const char *p);

static inline const char* fstab_path(void) {
        return secure_getenv("SYSTEMD_FSTAB") ?: "/etc/fstab";
}

bool fstab_is_bind(const char *options, const char *fstype);
