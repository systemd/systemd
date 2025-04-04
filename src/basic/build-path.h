/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int get_build_exec_dir(char **ret);

int invoke_callout_binary(const char *path, char *const argv[]);

int pin_callout_binary(const char *path, char **ret_path);
