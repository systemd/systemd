/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int home_mount_node(const char *node, const char *fstype, bool discard, unsigned long flags, const char *extra_mount_options);
int home_unshare_and_mkdir(void);
int home_unshare_and_mount(const char *node, const char *fstype, bool discard, unsigned long flags, const char *extra_mount_options);
int home_move_mount(const char *user_name_and_realm, const char *target);
int home_shift_uid(int dir_fd, const char *target, uid_t stored_uid, uid_t exposed_uid, int *ret_mount_fd);
