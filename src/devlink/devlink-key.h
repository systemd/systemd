/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "siphash24.h"

#include "devlink-kind.h"
#include "devlink-match.h"

typedef struct DevlinkKey {
        DevlinkKind kind;
        DevlinkMatchSet matchset;
        DevlinkMatch match;
} DevlinkKey;

void devlink_key_hash_func(const DevlinkKey *key, struct siphash *state);
int devlink_key_compare_func(const DevlinkKey *x, const DevlinkKey *y);
void devlink_key_copy_from_match(DevlinkKey *dst, const DevlinkMatch *src, DevlinkMatchSet matchset);
void devlink_key_copy_subkey(DevlinkKey *dst, const DevlinkKey *src, DevlinkMatchSet matchset);
int devlink_key_duplicate_from_match(DevlinkKey *dst, const DevlinkMatch *src, DevlinkMatchSet matchset);
int devlink_key_duplicate(DevlinkKey *dst, const DevlinkKey *src);
void devlink_key_init(DevlinkKey *key, DevlinkKind kind);
void devlink_key_fini(DevlinkKey *key);
void devlink_key_matchset_set(DevlinkKey *key, DevlinkMatchSet matchset);
int devlink_key_genl_append(sd_netlink_message *message, const DevlinkKey *key);
