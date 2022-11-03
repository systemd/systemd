/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>
***/

#include <stdbool.h>
#include <sys/types.h>

#include "label.h"
#include "macro.h"

#define SMACK_FLOOR_LABEL "_"
#define SMACK_STAR_LABEL  "*"

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

int mac_smack_fix_full(int atfd, const char *inode_path, const char *label_path, LabelFixFlags flags);
static inline int mac_smack_fix(const char *path, LabelFixFlags flags) {
        return mac_smack_fix_full(AT_FDCWD, path, path, flags);
}

const char* smack_attr_to_string(SmackAttr i) _const_;
SmackAttr smack_attr_from_string(const char *s) _pure_;
int mac_smack_read(const char *path, SmackAttr attr, char **label);
int mac_smack_read_fd(int fd, SmackAttr attr, char **label);
int mac_smack_apply(const char *path, SmackAttr attr, const char *label);
int mac_smack_apply_fd(int fd, SmackAttr attr, const char *label);
int mac_smack_apply_pid(pid_t pid, const char *label);
int mac_smack_copy(const char *dest, const char *src);

int rename_and_apply_smack_floor_label(const char *temp_path, const char *dest_path);
