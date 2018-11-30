/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "unit.h"

int unit_name_printf(Unit *u, const char* text, char **ret);
int unit_full_printf(Unit *u, const char *text, char **ret);
