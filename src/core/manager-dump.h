/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "manager.h"

void manager_dump_jobs_by_patterns(Manager *s, FILE *f, char **patterns, const char *prefix);
void manager_dump_units_by_patterns(Manager *s, FILE *f, char **patterns, const char *prefix);
void manager_dump(Manager *s, FILE *f, const char *prefix);
int manager_get_dump_string_by_patterns(Manager *m, char **patterns, char **ret);
void manager_test_summary(Manager *m);

static inline void manager_dump_jobs(Manager *s, FILE *f, const char *prefix) {
        manager_dump_jobs_by_patterns(s, f, NULL, prefix);
}

static inline void manager_dump_units(Manager *s, FILE *f, const char *prefix) {
        manager_dump_units_by_patterns(s, f, NULL, prefix);
}

static inline void manager_dump_by_patterns(Manager *m, FILE *f, char **patterns, const char *prefix) {
        manager_dump_units_by_patterns(m, f, patterns, prefix);
        manager_dump_jobs_by_patterns(m, f, patterns, prefix);
}

static inline int manager_get_dump_string(Manager *m, char **ret) {
        return manager_get_dump_string_by_patterns(m, NULL, ret);
}
