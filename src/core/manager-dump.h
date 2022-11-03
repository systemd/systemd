/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "manager.h"

void manager_dump_jobs(Manager *s, FILE *f, char **patterns, const char *prefix);
void manager_dump_units(Manager *s, FILE *f, char **patterns, const char *prefix);
void manager_dump(Manager *s, FILE *f, char **patterns, const char *prefix);
int manager_get_dump_string(Manager *m, char **patterns, char **ret);
void manager_test_summary(Manager *m);
