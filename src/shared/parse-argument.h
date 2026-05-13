/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int parse_boolean_argument(const char *optname, const char *s, bool *ret);
int parse_tristate_argument_with_auto(const char *optname, const char *s, int *ret);
int parse_json_argument(const char *s, sd_json_format_flags_t *ret);
int parse_path_argument(const char *path, bool suppress_root, char **arg);
int parse_signal_argument(const char *s, int *ret);
int parse_machine_argument(const char *s, const char **ret_host, BusTransport *ret_transport);
int parse_background_argument(const char *s, char **arg);
