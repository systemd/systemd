/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

/* Space for capability_to_string() in case we write out a numeric capability because we don't know the name
 * for it. "0x3e" is the largest string we might output, in both sensese of the word "largest": two chars for
 * "0x", two bytes for the hex value, and one trailing NUL byte. */
#define CAPABILITY_TO_STRING_MAX (2 + 2 + 1)

const char* capability_to_name(int id);
const char* capability_to_string(int id, char buf[static CAPABILITY_TO_STRING_MAX]);
#define CAPABILITY_TO_STRING(id) capability_to_string(id, (char[CAPABILITY_TO_STRING_MAX]) {})

int capability_from_name(const char *name);
int capability_list_length(void);

int capability_set_to_string(uint64_t set, char **ret);
int capability_set_to_string_negative(uint64_t set, char **ret);
int capability_set_to_strv(uint64_t set, char ***ret);
int capability_set_from_string(const char *s, uint64_t *ret);
