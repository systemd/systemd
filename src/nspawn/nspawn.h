/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int userns_lchown(const char *p, uid_t uid, gid_t gid);
int userns_mkdir(const char *root, const char *path, mode_t mode, uid_t uid, gid_t gid);
int make_run_host(const char *root);
