/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "macro.h"

extern int saved_argc;
extern char **saved_argv;

static inline void save_argc_argv(int argc, char **argv) {
        /* Protect against CVE-2021-4034 style attacks */
        assert_se(argc > 0);
        assert_se(argv);
        assert_se(argv[0]);

        saved_argc = argc;
        saved_argv = argv;
}

bool invoked_as(char *argv[], const char *token);
bool invoked_by_systemd(void);
bool argv_looks_like_help(int argc, char **argv);

int rename_process(const char name[]);
