/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int action_list_namespaces(const char *root);
int action_list_boots(void);
int action_verify(bool verbose);
int action_print_header(void);
int action_disk_usage(void);
int action_list_field_names(void);
int action_list_fields(char **matches);
