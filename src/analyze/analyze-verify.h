/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "execute.h"
#include "path-lookup.h"

typedef enum ReturnErrorOn {
        RETURN_ERROR_ON_NONE,                                 /* Never returns errors on syntax warnings */
        RETURN_ERROR_ON_ANY_WARNING,                          /* Returns errors when warnings arise in any associated unit */
        RETURN_ERROR_ON_WARNING_IN_SELECTED,                  /* Returns errors when warnings arise in the selected unit */
        RETURN_ERROR_ON_WARNING_IN_SELECTED_AND_DEPENDENCIES, /* Returns errors when warnings arise in the selected unit or its direct dependencies */
        _RETURN_ERROR_ON_MAX,
        _RETURN_ERROR_ON_INVALID = -EINVAL,
} ReturnErrorOn;

int verify_executable(Unit *u, const ExecCommand *exec);
int verify_units(char **filenames, UnitFileScope scope, bool check_man, bool run_generators, ReturnErrorOn return_error_on);

const char* return_error_on_to_string(ReturnErrorOn i) _const_;
ReturnErrorOn return_error_on_from_string(const char *s) _pure_;
