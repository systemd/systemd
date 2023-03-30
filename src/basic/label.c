/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>

#include "label.h"

static const LabelOps *label_ops = NULL;

void label_ops_set(const LabelOps *ops) {
        label_ops = ops;
}

int label_ops_pre(int dir_fd, const char *path, mode_t mode) {
        return label_ops ? label_ops->pre(dir_fd, path, mode) : 0;
}

int label_ops_post(int dir_fd, const char *path) {
        return label_ops ? label_ops->post(dir_fd, path) : 0;
}
