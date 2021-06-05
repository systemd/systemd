/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "execute.h"
#include "path-lookup.h"

int verify_executable(Unit *u, const ExecCommand *exec);
int verify_units(char **filenames, UnitFileScope scope, bool check_man, bool run_generators);
