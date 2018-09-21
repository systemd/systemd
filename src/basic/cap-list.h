/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

const char *capability_to_name(int id);
int capability_from_name(const char *name);
int capability_list_length(void);

int capability_set_to_string_alloc(uint64_t set, char **s);
int capability_set_from_string(const char *s, uint64_t *set);
