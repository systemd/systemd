/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "devlink-util.h"
#include "netlink-util.h"
#include "siphash24.h"

typedef enum DevlinkMatchBit {
        DEVLINK_MATCH_BIT_TEMP,
} DevlinkMatchBit;

typedef uint32_t DevlinkMatchSet;

typedef struct DevlinkMatch {
} DevlinkMatch;

struct Manager;
typedef struct Manager Manager;

typedef struct DevlinkMatchVTable {
        void (*free)(DevlinkMatch *match);
        bool (*check)(const DevlinkMatch *match);
        void (*log_prefix)(char **buf, int *len, const DevlinkMatch *match);
        void (*hash_func)(const DevlinkMatch *match, struct siphash *state);
        int (*compare_func)(const DevlinkMatch *x, const DevlinkMatch *y);
        void (*copy_func)(DevlinkMatch *dst, const DevlinkMatch *src);
        int (*duplicate_func)(DevlinkMatch *dst, const DevlinkMatch *src);
        int (*genl_read)(sd_netlink_message *message, Manager *m, DevlinkMatch *match);
        int (*genl_append)(sd_netlink_message *message, const DevlinkMatch *match);
} DevlinkMatchVTable;

extern const DevlinkMatchVTable devlink_match_dev_vtable;

void devlink_match_fini(DevlinkMatch *match);
bool devlink_match_check(const DevlinkMatch *match, DevlinkMatchSet matchset);
void devlink_match_log_prefix(char **pos, int *len, const DevlinkMatch *match, DevlinkMatchSet matchset);
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
