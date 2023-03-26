/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

typedef struct LabelOps {
        int (*pre)(int dir_fd, const char *path, mode_t mode);
        int (*post)(int dir_fd, const char *path);
} LabelOps;

extern const LabelOps *label_ops;

static inline int label_pre(int dir_fd, const char *path, mode_t mode) {
        return label_ops ? label_ops->pre(dir_fd, path, mode) : 0;
}

static inline int label_post(int dir_fd, const char *path) {
        return label_ops ? label_ops->post(dir_fd, path) : 0;
}
