/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "unit.h"

int unit_name_printf(const Unit *u, const char* text, char **ret);
int unit_full_printf(const Unit *u, const char *text, char **ret);
