/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "hashmap.h"
#include "user-util.h"

int bus_test_polkit(sd_bus_message *call, const char *action, const char **details, uid_t good_user, bool *_challenge, sd_bus_error *e);

int bus_verify_polkit_async_full(sd_bus_message *call, const char *action, const char **details, bool interactive, uid_t good_user, Hashmap **registry, sd_bus_error *error);
static inline int bus_verify_polkit_async(sd_bus_message *call, const char *action, const char **details, Hashmap **registry, sd_bus_error *ret_error) {
        return bus_verify_polkit_async_full(call, action, details, false, UID_INVALID, registry, ret_error);
}

Hashmap *bus_verify_polkit_async_registry_free(Hashmap *registry);
