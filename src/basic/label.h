/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

typedef struct LabelOps {
        int (*pre)(int dir_fd, const char *path, mode_t mode);
        int (*post)(int dir_fd, const char *path, bool created);
} LabelOps;

int label_ops_set(const LabelOps *label_ops);
void label_ops_reset(void);

int label_ops_pre(int dir_fd, const char *path, mode_t mode);
int label_ops_post(int dir_fd, const char *path, bool created);
