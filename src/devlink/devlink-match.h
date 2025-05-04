/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "siphash24.h"

#include "devlink-match-dev.h"
#include "devlink-match-port.h"

typedef enum DevlinkMatchBitPosition {
        DEVLINK_MATCH_BIT_POSITION_DEV,
        DEVLINK_MATCH_BIT_POSITION_COMMON_INDEX,
        DEVLINK_MATCH_BIT_POSITION_PORT_SPLIT,
        _DEVLINK_MATCH_BIT_POSITION_MAX,
        _DEVLINK_MATCH_BIT_POSITION_INVALID = -1,
} DevlinkMatchBitPosition;

typedef enum DevlinkMatchBit {
        DEVLINK_MATCH_BIT_DEV = 1 << DEVLINK_MATCH_BIT_POSITION_DEV,
        DEVLINK_MATCH_BIT_COMMON_INDEX = 1 << DEVLINK_MATCH_BIT_POSITION_COMMON_INDEX,
        DEVLINK_MATCH_BIT_PORT_SPLIT = 1 << DEVLINK_MATCH_BIT_POSITION_PORT_SPLIT,
} DevlinkMatchBit;

const char* devlink_match_bit_to_string(DevlinkMatchBit bit);

typedef uint32_t DevlinkMatchSet;

typedef struct DevlinkMatchCommon {
        uint32_t index;
        bool index_valid;
} DevlinkMatchCommon;

typedef struct DevlinkMatch {
        DevlinkMatchCommon common;
        DevlinkMatchDev dev;
        DevlinkMatchPort port;
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
extern const DevlinkMatchVTable devlink_match_port_index_vtable;
extern const DevlinkMatchVTable devlink_match_port_split_vtable;

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

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_index);

bool devlink_match_common_index_check(const DevlinkMatch *match, bool explicit);
void devlink_match_common_index_log_prefix(char **buf, int *len, const DevlinkMatch *match);
void devlink_match_common_index_hash_func(const DevlinkMatch *match, struct siphash *state);
int devlink_match_common_index_compare_func(const DevlinkMatch *x, const DevlinkMatch *y);
void devlink_match_common_index_copy_func(DevlinkMatch *dst, const DevlinkMatch *src);
int devlink_match_common_index_duplicate_func(DevlinkMatch *dst, const DevlinkMatch *src);
