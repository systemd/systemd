/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "siphash24.h"

typedef enum DevlinkMatchBitPosition {
        DEVLINK_MATCH_BIT_POSITION_TEMP,
        _DEVLINK_MATCH_BIT_POSITION_MAX,
        _DEVLINK_MATCH_BIT_POSITION_INVALID = -1,
} DevlinkMatchBitPosition;

typedef enum DevlinkMatchBit {
        DEVLINK_MATCH_BIT_TEMP,
} DevlinkMatchBit;

const char* devlink_match_bit_to_string(DevlinkMatchBit bit);

typedef uint32_t DevlinkMatchSet;

typedef struct DevlinkMatch {
} DevlinkMatch;

struct Manager;
typedef struct Manager Manager;

typedef struct DevlinkMatchVTable {
        DevlinkMatchBit bit;
        void (*free)(DevlinkMatch *match);
        bool (*check)(const DevlinkMatch *match, bool explicit);
        void (*log_prefix)(char **buf, int *len, const DevlinkMatch *match);
        void (*hash_func)(const DevlinkMatch *match, struct siphash *state);
        int (*compare_func)(const DevlinkMatch *x, const DevlinkMatch *y);
        void (*copy_func)(DevlinkMatch *dst, const DevlinkMatch *src);
        int (*duplicate_func)(DevlinkMatch *dst, const DevlinkMatch *src);
        int (*genl_read)(sd_netlink_message *message, Manager *m, DevlinkMatch *match);
        int (*genl_append)(sd_netlink_message *message, const DevlinkMatch *match);
} DevlinkMatchVTable;

extern const DevlinkMatchVTable devlink_match_dev_vtable;

typedef enum DevlinkMatchCheckResult {
        DEVLINK_MATCH_CHECK_RESULT_MATCH,
        DEVLINK_MATCH_CHECK_RESULT_INSUFFICIENT_MATCH,
        DEVLINK_MATCH_CHECK_RESULT_EXTRA_MATCH,
        _DEVLINK_MATCH_CHECK_RESULT_MAX,
        _DEVLINK_MATCH_CHECK_RESULT_INVALID = -EINVAL,
} DevlinkMatchCheckResult;

void devlink_match_fini(DevlinkMatch *match);
DevlinkMatchCheckResult devlink_match_check(
        const DevlinkMatch *match,
        DevlinkMatchSet matchset,
        DevlinkMatchBit *first_extra_bit);
void devlink_match_log_prefix(
        char **pos,
        int *len,
        const DevlinkMatch *match,
        DevlinkMatchSet matchset);
void devlink_match_hash(
                const DevlinkMatch *match,
                DevlinkMatchSet matchset,
                struct siphash *state);
int devlink_match_compare(
                const DevlinkMatch *x,
                const DevlinkMatch *y,
                DevlinkMatchSet matchset);
int devlink_match_copy(
                DevlinkMatch *dst,
                const DevlinkMatch *src,
                DevlinkMatchSet matchset);
int devlink_match_duplicate(
                DevlinkMatch *x,
                const DevlinkMatch *y,
                DevlinkMatchSet matchset);
void devlink_match_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match,
                DevlinkMatchSet *matchset);
int devlink_match_genl_append(
                sd_netlink_message *message,
                const DevlinkMatch *match,
                DevlinkMatchSet matchset);
