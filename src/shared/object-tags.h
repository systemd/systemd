/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#define OBJECT_TAGS_MAX 1024U
#define OBJECT_TAG_GLOBS_MAX 64U

bool object_tag_is_valid(const char *s);
int object_tag_list_is_valid(char **l, bool to_add);
int object_tags_from_string(const char *s, const char *separators, bool graceful, char ***ret);
int object_tags_from_strv(char **l, bool graceful, char ***ret);

int object_tags_edit(char* const *base, char* const *add, char* const *remove, char ***ret);

static inline int machine_tags_from_string(const char *s, bool graceful, char ***ret) {
        return object_tags_from_string(s, ":", graceful, ret);
}
int machine_tags_config_files(const char *root, ConfFile ***ret_files, size_t *ret_n_files);
int machine_tags_apply_config(const char *root, char * const *base, char ***ret);
