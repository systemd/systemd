/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "macro.h"

typedef enum ImportType {
        IMPORT_RAW,
        IMPORT_TAR,
        _IMPORT_TYPE_MAX,
        _IMPORT_TYPE_INVALID = -EINVAL,
} ImportType;

typedef enum ImportVerify {
        IMPORT_VERIFY_NO,
        IMPORT_VERIFY_CHECKSUM,
        IMPORT_VERIFY_SIGNATURE,
        _IMPORT_VERIFY_MAX,
        _IMPORT_VERIFY_INVALID = -EINVAL,
} ImportVerify;

int import_url_last_component(const char *url, char **ret);

int import_url_change_suffix(const char *url, size_t n_drop_components, const char *suffix, char **ret);

static inline int import_url_change_last_component(const char *url, const char *suffix, char **ret) {
        return import_url_change_suffix(url, 1, suffix, ret);
}

static inline int import_url_append_component(const char *url, const char *suffix, char **ret) {
        return import_url_change_suffix(url, 0, suffix, ret);
}

const char* import_type_to_string(ImportType v) _const_;
ImportType import_type_from_string(const char *s) _pure_;

const char* import_verify_to_string(ImportVerify v) _const_;
ImportVerify import_verify_from_string(const char *s) _pure_;

int tar_strip_suffixes(const char *name, char **ret);
int raw_strip_suffixes(const char *name, char **ret);

int import_assign_pool_quota_and_warn(const char *path);

int import_set_nocow_and_log(int fd, const char *path);
