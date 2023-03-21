/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "execute.h"
#include "path-lookup.h"

typedef enum RecursiveErrors {
        RECURSIVE_ERRORS_YES,               /* Look for errors in all associated units */
        RECURSIVE_ERRORS_NO,                /* Don't look for errors in any but the selected unit */
        RECURSIVE_ERRORS_ONE,               /* Look for errors in the selected unit and its direct dependencies */
        _RECURSIVE_ERRORS_MAX,
        _RECURSIVE_ERRORS_INVALID = -EINVAL,
} RecursiveErrors;

int verify_generate_path(char **var, char **filenames);
int verify_prepare_filename(const char *filename, char **ret);
int verify_executable(Unit *u, const ExecCommand *exec, const char *root);
int verify_units(char **filenames, RuntimeScope scope, bool check_man, bool run_generators, RecursiveErrors recursive_errors, const char *root);

const char* recursive_errors_to_string(RecursiveErrors i) _const_;
RecursiveErrors recursive_errors_from_string(const char *s) _pure_;
