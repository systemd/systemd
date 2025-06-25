/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>
***/

#include "forward.h"

typedef enum SmackAttr {
        SMACK_ATTR_ACCESS,
        SMACK_ATTR_EXEC,
        SMACK_ATTR_MMAP,
        SMACK_ATTR_TRANSMUTE,
        SMACK_ATTR_IPIN,
        SMACK_ATTR_IPOUT,
        _SMACK_ATTR_MAX,
        _SMACK_ATTR_INVALID = -EINVAL,
} SmackAttr;

bool mac_smack_use(void);

int mac_smack_read_at(int fd, const char *path, SmackAttr attr, char **ret);
int mac_smack_apply_at(int fd, const char *path, SmackAttr attr, const char *label);

int mac_smack_apply_pid(pid_t pid, const char *label);

int mac_smack_fix_full(int atfd, const char *inode_path, const char *label_path, LabelFixFlags flags);

int mac_smack_init(void);

static inline int mac_smack_read(const char *path, SmackAttr attr, char **ret) {
        return mac_smack_read_at(AT_FDCWD, path, attr, ret);
}
static inline int mac_smack_read_fd(int fd, SmackAttr attr, char **ret) {
        return mac_smack_read_at(fd, NULL, attr, ret);
}

static inline int mac_smack_apply(const char *path, SmackAttr attr, const char *label) {
        return mac_smack_apply_at(AT_FDCWD, path, attr, label);
}
static inline int mac_smack_apply_fd(int fd, SmackAttr attr, const char *label) {
        return mac_smack_apply_at(fd, NULL, attr, label);
}

int mac_smack_fix(const char *path, LabelFixFlags flags);

int renameat_and_apply_smack_floor_label(int fdf, const char *from, int fdt, const char *to);
static inline int rename_and_apply_smack_floor_label(const char *from, const char *to) {
        return renameat_and_apply_smack_floor_label(AT_FDCWD, from, AT_FDCWD, to);
}
