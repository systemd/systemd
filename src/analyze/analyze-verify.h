/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "path-lookup.h"

int verify_units(char **filenames, UnitFileScope scope, bool check_man, bool run_generators);
