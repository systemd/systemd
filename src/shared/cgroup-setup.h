/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int cg_weight_parse(const char *s, uint64_t *ret);
int cg_cpu_weight_parse(const char *s, uint64_t *ret);

int cg_trim(const char *path, bool delete_root);

int cg_create(const char *path);
int cg_attach(const char *path, pid_t pid);
int cg_fd_attach(int fd, pid_t pid);
int cg_create_and_attach(const char *path, pid_t pid);

int cg_set_access(const char *path, uid_t uid, gid_t gid);
int cg_set_access_recursive(const char *path, uid_t uid, gid_t gid);

int cg_enable(CGroupMask supported, CGroupMask mask, const char *p, CGroupMask *ret_result_mask);

int cg_migrate(const char *from, const char *to, CGroupFlags flags);

int cg_has_legacy(void);
int cg_is_ready(void);
