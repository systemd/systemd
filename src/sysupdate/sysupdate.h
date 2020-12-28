/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

extern bool arg_sync;
extern uint64_t arg_instances_max;
extern char *arg_root;

static inline const char* import_binary_path(void) {
        return secure_getenv("SYSTEMD_IMPORT_PATH") ?: SYSTEMD_IMPORT_PATH;
}

static inline const char* import_fs_binary_path(void) {
        return secure_getenv("SYSTEMD_IMPORT_FS_PATH") ?: SYSTEMD_IMPORT_FS_PATH;
}

static inline const char *pull_binary_path(void) {
        return secure_getenv("SYSTEMD_PULL_PATH") ?: SYSTEMD_PULL_PATH;
}
