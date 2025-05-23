/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

extern int saved_argc;
extern char **saved_argv;

void save_argc_argv(int argc, char **argv);

bool invoked_as(char *argv[], const char *token);
bool invoked_by_systemd(void);
bool argv_looks_like_help(int argc, char **argv);

int rename_process(const char name[]);
