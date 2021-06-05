/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int telinit_parse_argv(int argc, char *argv[]);
int start_with_fallback(void);
int reload_with_fallback(void);
int exec_telinit(char *argv[]);
