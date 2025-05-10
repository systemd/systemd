/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "devlink-util.h"
#include "netlink-util.h"
#include "siphash24.h"

#include "devlink-match-dev.h"
#include "devlink-match-port.h"

typedef enum DevlinkMatchBit {
        DEVLINK_MATCH_BIT_DEV = 1 << 0,
        DEVLINK_MATCH_BIT_PORT_INDEX = 1 << 1,
        DEVLINK_MATCH_BIT_PORT_SPLIT = 1 << 2,
        DEVLINK_MATCH_BIT_PORT_IFNAME = 1 << 3,
        DEVLINK_MATCH_BIT_PARAM = 1 << 4,
        DEVLINK_MATCH_BIT_HEALTH_REPORTER = 1 << 5,
} DevlinkMatchBit;

typedef uint32_t DevlinkMatchSet;

typedef struct DevlinkMatchCommon {
        uint32_t index;
        bool index_valid;
        char *name;
} DevlinkMatchCommon;

typedef struct DevlinkMatch {
        DevlinkMatchCommon common;
        DevlinkMatchDev dev;
        DevlinkMatchPort port;
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
extern const DevlinkMatchVTable devlink_match_port_index_vtable;
extern const DevlinkMatchVTable devlink_match_port_split_vtable;
extern const DevlinkMatchVTable devlink_match_port_ifname_vtable;
extern const DevlinkMatchVTable devlink_match_param_vtable;
extern const DevlinkMatchVTable devlink_match_health_reporter_vtable;

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

CONFIG_PARSER_PROTOTYPE(config_parse_devlink_index);

bool devlink_match_common_index_check(const DevlinkMatch *match);
void devlink_match_common_index_log_prefix(char **buf, int *len, const DevlinkMatch *match);
void devlink_match_common_index_hash_func(const DevlinkMatch *match, struct siphash *state);
int devlink_match_common_index_compare_func(const DevlinkMatch *x, const DevlinkMatch *y);
void devlink_match_common_index_copy_func(DevlinkMatch *dst, const DevlinkMatch *src);
int devlink_match_common_index_duplicate_func(DevlinkMatch *dst, const DevlinkMatch *src);
void devlink_match_common_name_free(DevlinkMatch *match);
bool devlink_match_common_name_check(const DevlinkMatch *match);
void devlink_match_common_name_log_prefix(char **buf, int *len, const DevlinkMatch *match);
void devlink_match_common_name_hash_func(const DevlinkMatch *match, struct siphash *state);
int devlink_match_common_name_compare_func(const DevlinkMatch *x, const DevlinkMatch *y);
void devlink_match_common_name_copy_func(DevlinkMatch *dst, const DevlinkMatch *src);
