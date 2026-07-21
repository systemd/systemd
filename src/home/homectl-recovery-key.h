/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct RecoveryKeyFile {
        int fd;
        int dir_fd;
        char *filename;
        char *path;
        bool remove;
} RecoveryKeyFile;

#define RECOVERY_KEY_FILE_NULL ((RecoveryKeyFile) { .fd = -EBADF, .dir_fd = -EBADF })

int identity_add_recovery_key(sd_json_variant **v, char **ret_recovery_key);
void show_recovery_key(const char *recovery_key);
void recovery_key_file_done(RecoveryKeyFile *f);
int recovery_key_file_prepare(RecoveryKeyFile *f, const char *path);
int recovery_key_file_write(RecoveryKeyFile *f, const char *recovery_key);
