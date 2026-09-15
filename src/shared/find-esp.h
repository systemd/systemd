/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "forward.h"

int find_esp_and_warn_at_full(int rfd, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_esp_and_warn_full(const char *root, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);

static inline int find_esp_and_warn_at(int rfd, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd) {
        return find_esp_and_warn_at_full(
                        rfd,
                        path,
                        unprivileged_mode,
                        ret_path,
                        ret_fd,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid= */ NULL,
                        /* ret_devid= */ NULL);
}
static inline int find_esp_and_warn(const char *root, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd) {
        return find_esp_and_warn_full(
                        root,
                        path,
                        unprivileged_mode,
                        ret_path,
                        ret_fd,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid= */ NULL,
                        /* ret_devid= */ NULL);
}

int find_xbootldr_and_warn_at_full(int rfd, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_xbootldr_and_warn_full(const char *root, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd, sd_id128_t *ret_uuid, dev_t *ret_devid);

static inline int find_xbootldr_and_warn_at(int rfd, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd) {
        return find_xbootldr_and_warn_at_full(rfd, path, unprivileged_mode, ret_path, ret_fd, /* ret_uuid= */ NULL, /* ret_devid= */ NULL);
}
static inline int find_xbootldr_and_warn(const char *root, const char *path, int unprivileged_mode, char **ret_path, int *ret_fd) {
        return find_xbootldr_and_warn_full(root, path, unprivileged_mode, ret_path, ret_fd, /* ret_uuid= */ NULL, /* ret_devid= */ NULL);
}
