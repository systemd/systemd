/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "logs-show.h"

/* The lists below are supposed to return the superset of unit names possibly matched by rules added with
 * add_matches_for_unit() and add_matches_for_user_unit(). */
#define SYSTEM_UNITS                 \
        "_SYSTEMD_UNIT\0"            \
        "UNIT\0"                     \
        "OBJECT_SYSTEMD_UNIT\0"

#define SYSTEM_UNITS_FULL            \
        SYSTEM_UNITS                 \
        "COREDUMP_UNIT\0"            \
        "_SYSTEMD_SLICE\0"

#define USER_UNITS                   \
        "_SYSTEMD_USER_UNIT\0"       \
        "USER_UNIT\0"                \
        "OBJECT_SYSTEMD_USER_UNIT\0"

#define USER_UNITS_FULL              \
        USER_UNITS                   \
        "COREDUMP_USER_UNIT\0"       \
        "_SYSTEMD_USER_SLICE\0"

char* format_timestamp_maybe_utc(char *buf, size_t l, usec_t t);
int acquire_journal(sd_journal **ret);
bool journal_boot_has_effect(sd_journal *j);
int journal_acquire_boot(sd_journal *j);
int get_possible_units(sd_journal *j, const char *fields, char * const *patterns, Set **ret);
int acquire_unit(sd_journal *j, const char *option_name, const char **ret_unit, LogIdType *ret_type);
int journal_acquire_invocation(sd_journal *j);
