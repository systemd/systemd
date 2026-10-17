/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

/* The constraints a file system declares about itself via the user.validatefs.* extended attributes on its
 * root inode, as set by systemd-repart's AddValidateFS= logic */
typedef struct ValidateFields {
        sd_id128_t *gpt_type_uuid;
        size_t n_gpt_type_uuid;
        char **gpt_label;
        char **mount_point;
} ValidateFields;

void validate_fields_done(ValidateFields *f);

int validate_fields_read(int fd, int log_level, ValidateFields *ret);

bool validate_fields_need_gpt(const ValidateFields *f);

int validate_fields_check_mount_point(const ValidateFields *f, const char *root, const char *path, int log_level);
int validate_fields_check_gpt_label(const ValidateFields *f, const char *label, int log_level);
int validate_fields_check_gpt_type(const ValidateFields *f, const sd_id128_t *type, int log_level);
