/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "sd-varlink.h"

#include "hashmap.h"
#include "user-util.h"

typedef enum PolkitFlags {
        POLKIT_ALLOW_INTERACTIVE = 1 << 0, /* Allow interactive auth (typically not required, because can be derived from bus message/link automatically) */
        POLKIT_ALWAYS_QUERY      = 1 << 1, /* Query polkit even if client is privileged */
        POLKIT_DEFAULT_ALLOW     = 1 << 2, /* If polkit is not around, assume "allow" rather than the usual "deny" */
        POLKIT_DONT_REPLY        = 1 << 3, /* Varlink: don't immediately propagate polkit error to the Varlink client */
        _POLKIT_MASK_PUBLIC      = POLKIT_ALLOW_INTERACTIVE | POLKIT_ALWAYS_QUERY, /* polkit accepts these flags verbatim */
} PolkitFlags;

int bus_test_polkit(sd_bus_message *call, const char *action, const char **details, uid_t good_user, bool *_challenge, sd_bus_error *e);

int bus_verify_polkit_async_full(sd_bus_message *call, const char *action, const char **details, uid_t good_user, PolkitFlags flags, Hashmap **registry, sd_bus_error *error);
static inline int bus_verify_polkit_async(sd_bus_message *call, const char *action, const char **details, Hashmap **registry, sd_bus_error *error) {
        return bus_verify_polkit_async_full(call, action, details, UID_INVALID, 0, registry, error);
}

int varlink_verify_polkit_async_full(sd_varlink *link, sd_bus *bus, const char *action, const char **details, uid_t good_user, PolkitFlags flags, Hashmap **registry);
static inline int varlink_verify_polkit_async(sd_varlink *link, sd_bus *bus, const char *action, const char **details, Hashmap **registry) {
        return varlink_verify_polkit_async_full(link, bus, action, details, UID_INVALID, 0, registry);
}

/* A sd_json_dispatch_field initializer that makes sure the allowInteractiveAuthentication boolean field we want for
 * polkit support in Varlink calls is ignored while regular dispatching (and does not result in errors
 * regarding unexpected fields) */
#define VARLINK_DISPATCH_POLKIT_FIELD {                          \
                .name = "allowInteractiveAuthentication",        \
                .type = SD_JSON_VARIANT_BOOLEAN,                 \
        }

/* Generates the right Varlink introspection field for the allowInteractiveAuthentication field above. To be used in Varlink IDL definitions. */
#define VARLINK_DEFINE_POLKIT_INPUT                                     \
        SD_VARLINK_FIELD_COMMENT("Controls whether interactive authentication (via polkit) shall be allowed. If unspecified defaults to false."), \
        SD_VARLINK_DEFINE_INPUT(allowInteractiveAuthentication, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE)

bool varlink_has_polkit_action(sd_varlink *link, const char *action, const char **details, Hashmap **registry);
