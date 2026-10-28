/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#define MACHINE_TAGS_MAX 1024U
#define MACHINE_TAG_GLOBS_MAX 64U

bool machine_tag_is_valid(const char *s);
int machine_tag_list_is_valid(char **l, bool to_add);
int machine_tags_from_string(const char *s, bool graceful, char ***ret);
int machine_tags_from_strv(char **l, bool graceful, char ***ret);

int machine_tags_edit(char* const *base, char* const *add, char* const *remove, char ***ret);
int machine_tags_apply_config(const char *root, char * const *base, char ***ret);
