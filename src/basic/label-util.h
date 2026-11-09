/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct LabelOps {
        int (*pre)(int dir_fd, const char *path, mode_t mode, LabelContext *label_context) _sync_;
        int (*post)(int dir_fd, const char *path, bool created, LabelContext *label_context) _sync_;
} LabelOps;

_sync_ int label_ops_set(const LabelOps *label_ops);
_sync_ void label_ops_reset(void);

_sync_ int label_ops_pre(int dir_fd, const char *path, mode_t mode, LabelContext *label_context);
_sync_ int label_ops_post(int dir_fd, const char *path, bool created, LabelContext *label_context);
