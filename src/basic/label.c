/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "label.h"

#define POSSIBLE_LABEL_OPS 2 /* SELinux and Smack */
static const LabelOps *label_ops[POSSIBLE_LABEL_OPS];

int label_ops_set(const LabelOps *ops) {
        int i;

        assert(ops);

        for (i = 0; i < POSSIBLE_LABEL_OPS; i++) {
                if (!label_ops[i]) {
                        label_ops[i] = ops;
                        return 0;
                }
        }
        return -EBUSY;
}

void label_ops_reset(void) {
        int i;

        for (i = 0; i < POSSIBLE_LABEL_OPS; i++)
                label_ops[i] = NULL;
}

int label_ops_pre(int dir_fd, const char *path, mode_t mode) {
        int i;
        int r;

        for (i = 0; i < POSSIBLE_LABEL_OPS; i++) {
                if (label_ops[i] && label_ops[i]->pre) {
                        r = label_ops[i]->pre(dir_fd, path, mode);
                        if (r)
                                return r;
                }
        }
        return 0;
}

int label_ops_post(int dir_fd, const char *path, bool created) {
        int i;
        int r;

        for (i = 0; i < POSSIBLE_LABEL_OPS; i++) {
                if (label_ops[i] && label_ops[i]->post) {
                        r = label_ops[i]->post(dir_fd, path, created);
                        if (r)
                                return r;
                }
        }
        return 0;
}
