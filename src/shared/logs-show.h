/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "shared-forward.h"

typedef struct LogId {
        sd_id128_t id; /* boot ID or invocation ID */
        usec_t first_usec;
        usec_t last_usec;
} LogId;

typedef enum LogIdType {
        LOG_BOOT_ID,
        LOG_SYSTEM_UNIT_INVOCATION_ID,
        LOG_USER_UNIT_INVOCATION_ID,
        _LOG_ID_TYPE_MAX,
        _LOG_ID_TYPE_INVALID = -EINVAL,
} LogIdType;

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

int add_matches_for_invocation_id(sd_journal *j, sd_id128_t id);

typedef enum MatchUnitFlag {
        MATCH_UNIT_SLICE          = 1 << 0,
        MATCH_UNIT_COREDUMP       = 1 << 1,
        MATCH_UNIT_COREDUMP_UID   = 1 << 2,

        MATCH_UNIT_ALL = MATCH_UNIT_SLICE | MATCH_UNIT_COREDUMP | MATCH_UNIT_COREDUMP_UID,
} MatchUnitFlag;

int add_matches_for_unit_full(sd_journal *j, MatchUnitFlag flags, const char *unit);
static inline int add_matches_for_unit(sd_journal *j, const char *unit) {
        return add_matches_for_unit_full(j, MATCH_UNIT_ALL, unit);
}
int add_matches_for_user_unit_full(sd_journal *j, MatchUnitFlag flags, uid_t uid, const char *unit);
static inline int add_matches_for_user_unit(sd_journal *j, const char *unit) {
        return add_matches_for_user_unit_full(j, MATCH_UNIT_ALL, UID_INVALID, unit);
}

int show_journal_by_unit(
                FILE *f,
                const char *unit,
                const char *namespace,
                OutputMode mode,
                unsigned n_columns,
                usec_t not_before,
                unsigned how_many,
                OutputFlags flags,
                int journal_open_flags,
                bool system_unit,
                bool *ellipsized);

void json_escape(
                FILE *f,
                const char* p,
                size_t l,
                OutputFlags flags);

int journal_entry_to_json(sd_journal *j, OutputFlags flags, const Set *output_fields, sd_json_variant **ret);

int discover_next_id(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,  /* optional, used when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                const char *unit,    /* mandatory when type == JOURNAL_{SYSTEM,USER}_UNIT_INVOCATION_ID */
                sd_id128_t previous_id,
                bool advance_older,
                LogId *ret);

int journal_find_log_id(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,
                const char *unit,
                sd_id128_t id,
                int offset,
                sd_id128_t *ret);

static inline int journal_find_boot(
                sd_journal *j,
                sd_id128_t id,
                int offset,
                sd_id128_t *ret) {

        return journal_find_log_id(j, LOG_BOOT_ID,
                                   /* boot_id= */ SD_ID128_NULL, /* unit= */ NULL,
                                   id, offset, ret);
}

int journal_get_log_ids(
                sd_journal *j,
                LogIdType type,
                sd_id128_t boot_id,
                const char *unit,
                bool advance_older,
                size_t max_ids,
                LogId **ret_ids,
                size_t *ret_n_ids);

static inline int journal_get_boots(
                sd_journal *j,
                bool advance_older,
                size_t max_ids,
                LogId **ret_ids,
                size_t *ret_n_ids) {

        return journal_get_log_ids(j, LOG_BOOT_ID,
                                   /* boot_id= */ SD_ID128_NULL, /* unit= */ NULL,
                                   advance_older, max_ids,
                                   ret_ids, ret_n_ids);
}

void journal_browse_prepare(void);
