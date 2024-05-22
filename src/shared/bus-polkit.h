/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "hashmap.h"
#include "user-util.h"
#include "varlink.h"

typedef enum PolkitFLags {
        POLKIT_ALLOW_INTERACTIVE = 1 << 0, /* Allow interactive auth (typically not required, because can be derived from bus message/link automatically) */
        POLKIT_ALWAYS_QUERY      = 1 << 1, /* Query polkit even if client is privileged */
        POLKIT_DEFAULT_ALLOW     = 1 << 2, /* If polkit is not around, assume "allow" rather than the usual "deny" */
} PolkitFlags;

int bus_test_polkit(sd_bus_message *call, const char *action, const char **details, uid_t good_user, bool *_challenge, sd_bus_error *e);

int bus_verify_polkit_async_full(sd_bus_message *call, const char *action, const char **details, uid_t good_user, PolkitFlags flags, Hashmap **registry, sd_bus_error *error);
static inline int bus_verify_polkit_async(sd_bus_message *call, const char *action, const char **details, Hashmap **registry, sd_bus_error *error) {
        return bus_verify_polkit_async_full(call, action, details, UID_INVALID, 0, registry, error);
}

int varlink_verify_polkit_async_full(Varlink *link, sd_bus *bus, const char *action, const char **details, uid_t good_user, PolkitFlags flags, Hashmap **registry);
static inline int varlink_verify_polkit_async(Varlink *link, sd_bus *bus, const char *action, const char **details, Hashmap **registry) {
        return varlink_verify_polkit_async_full(link, bus, action, details, UID_INVALID, 0, registry);
}

/* A JsonDispatch initializer that makes sure the allowInteractiveAuthentication boolean field we want for
 * polkit support in Varlink calls is ignored while regular dispatching (and does not result in errors
 * regarding unexpected fields) */
#define VARLINK_DISPATCH_POLKIT_FIELD {                          \
                .name = "allowInteractiveAuthentication",        \
                .type = JSON_VARIANT_BOOLEAN,                    \
        }

bool varlink_has_polkit_action(Varlink *link, const char *action, const char **details, Hashmap **registry);
