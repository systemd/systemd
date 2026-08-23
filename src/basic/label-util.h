/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct LabelOps {
        int (*pre)(int dir_fd, const char *path, mode_t mode, LabelContext *label_context);
        int (*post)(int dir_fd, const char *path, bool created, LabelContext *label_context);
} LabelOps;

int label_ops_set(const LabelOps *label_ops);
void label_ops_reset(void);

int label_ops_pre(int dir_fd, const char *path, mode_t mode, LabelContext *label_context);
int label_ops_post(int dir_fd, const char *path, bool created, LabelContext *label_context);
