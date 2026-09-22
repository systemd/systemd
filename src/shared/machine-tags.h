/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#define MACHINE_TAGS_MAX 1024U

bool machine_tag_is_valid(const char *s);
int machine_tag_list_is_valid(char **l);
int machine_tags_from_string(const char *s, bool graceful, char ***ret);
int machine_tags_from_strv(char **l, bool graceful, char ***ret);
