/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int parse_path_argument(const char *path, bool suppress_root, char **arg);
int parse_signal_argument(const char *s, int *ret);
