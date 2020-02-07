/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "time-util.h"
#include "user-record.h"

bool suitable_user_name(const char *name);
int suitable_realm(const char *realm);
int suitable_image_path(const char *path);

int split_user_name_realm(const char *t, char **ret_user_name, char **ret_realm);

int bus_message_append_secret(sd_bus_message *m, UserRecord *secret);

/* Many of our operations might be slow due to crypto, fsck, recursive chown() and so on. For these
 * operations permit a *very* long time-out */
#define HOME_SLOW_BUS_CALL_TIMEOUT_USEC (2*USEC_PER_MINUTE)

int test_password_one(const char *hashed_password, const char *password);
int test_password_many(char **hashed_password, const char *password);
