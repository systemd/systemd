/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "hash-funcs.h"
#include "time-util.h"
#include "user-record.h"

/* Flags supported by UpdateEx() */
#define SD_HOMED_UPDATE_OFFLINE (UINT64_C(1) << 0)
#define SD_HOMED_UPDATE_FLAGS_ALL (SD_HOMED_UPDATE_OFFLINE)

/* Flags supported by CreateHomeEx() */
#define SD_HOMED_CREATE_FLAGS_ALL (0)

/* Put some limits on disk sizes: not less than 5M, not more than 5T */
#define USER_DISK_SIZE_MIN (UINT64_C(5)*1024*1024)
#define USER_DISK_SIZE_MAX (UINT64_C(5)*1024*1024*1024*1024)

/* The default disk size to use when nothing else is specified, relative to free disk space. We calculate
 * this from the default rebalancing weights, so that what we create initially doesn't immediately require
 * rebalancing. */
#define USER_DISK_SIZE_DEFAULT_PERCENT ((unsigned) ((100 * REBALANCE_WEIGHT_DEFAULT) / (REBALANCE_WEIGHT_DEFAULT + REBALANCE_WEIGHT_BACKING)))

/* This should be 83% right now, i.e. 100 of (100 + 20). Let's protect us against accidental changes. */
assert_cc(USER_DISK_SIZE_DEFAULT_PERCENT == 83U);

extern const struct hash_ops blob_fd_hash_ops;

bool suitable_user_name(const char *name);
int suitable_realm(const char *realm);
int suitable_image_path(const char *path);

bool supported_fstype(const char *fstype);

int split_user_name_realm(const char *t, char **ret_user_name, char **ret_realm);

int bus_message_append_secret(sd_bus_message *m, UserRecord *secret);

/* Many of our operations might be slow due to crypto, fsck, recursive chown() and so on. For these
 * operations permit a *very* long timeout */
#define HOME_SLOW_BUS_CALL_TIMEOUT_USEC (2*USEC_PER_MINUTE)

const char* home_record_dir(void);
const char* home_system_blob_dir(void);
