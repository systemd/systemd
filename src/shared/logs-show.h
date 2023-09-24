/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "sd-id128.h"
#include "sd-journal.h"

#include "macro.h"
#include "output-mode.h"
#include "time-util.h"

typedef struct BootId {
        sd_id128_t id;
        usec_t first_usec;
        usec_t last_usec;
} BootId;

int show_journal_entry(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                OutputFlags flags,
                Set *output_fields,
                const size_t highlight[2],
                bool *ellipsized,
                dual_timestamp *previous_display_ts,
                sd_id128_t *previous_boot_id);
int show_journal(
                FILE *f,
                sd_journal *j,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                OutputFlags flags,
                bool *ellipsized);

int add_match_boot_id(sd_journal *j, sd_id128_t id);
int add_match_this_boot(sd_journal *j, const char *machine);

int add_matches_for_unit(
                sd_journal *j,
                const char *unit);

int add_matches_for_user_unit(
                sd_journal *j,
                const char *unit,
                uid_t uid);

int show_journal_by_unit(
                FILE *f,
                const char *unit,
                const char *namespace,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                uid_t uid,
                OutputFlags flags,
                int journal_open_flags,
                bool system_unit,
                bool *ellipsized);

void json_escape(
                FILE *f,
                const char* p,
                size_t l,
                OutputFlags flags);

int journal_find_boot_by_id(sd_journal *j, sd_id128_t boot_id);
int journal_find_boot_by_offset(sd_journal *j, int offset, sd_id128_t *ret);
int journal_get_boots(sd_journal *j, BootId **ret_boots, size_t *ret_n_boots);
