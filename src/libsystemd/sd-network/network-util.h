/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "constants.h"
#include "macro.h"

#define NETWORK_DIRS ((const char* const*) CONF_PATHS_STRV("systemd/network"))
#define NETWORK_DIRS_NULSTR CONF_PATHS_NULSTR("systemd/network")

bool network_is_online(void);

typedef enum AddressFamily {
        /* This is a bitmask, though it usually doesn't feel that way! */
        ADDRESS_FAMILY_NO             = 0,
        ADDRESS_FAMILY_IPV4           = 1 << 0,
        ADDRESS_FAMILY_IPV6           = 1 << 1,
        ADDRESS_FAMILY_YES            = ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_IPV6,
        _ADDRESS_FAMILY_MAX,
        _ADDRESS_FAMILY_INVALID = -EINVAL,
} AddressFamily;

static inline AddressFamily AF_TO_ADDRESS_FAMILY(int af) {
        switch (af) {
        case AF_INET:
                return ADDRESS_FAMILY_IPV4;
        case AF_INET6:
                return ADDRESS_FAMILY_IPV6;
        default:
                return ADDRESS_FAMILY_NO;
        }
}

typedef enum LinkOperationalState {
        LINK_OPERSTATE_MISSING,
        LINK_OPERSTATE_OFF,
        LINK_OPERSTATE_NO_CARRIER,
        LINK_OPERSTATE_DORMANT,
        LINK_OPERSTATE_DEGRADED_CARRIER,
        LINK_OPERSTATE_CARRIER,
        LINK_OPERSTATE_DEGRADED,
        LINK_OPERSTATE_ENSLAVED,
        LINK_OPERSTATE_ROUTABLE,
        _LINK_OPERSTATE_MAX,
        _LINK_OPERSTATE_INVALID = -EINVAL,
} LinkOperationalState;

typedef enum LinkCarrierState {
        LINK_CARRIER_STATE_OFF              = LINK_OPERSTATE_OFF,
        LINK_CARRIER_STATE_NO_CARRIER       = LINK_OPERSTATE_NO_CARRIER,
        LINK_CARRIER_STATE_DORMANT          = LINK_OPERSTATE_DORMANT,
        LINK_CARRIER_STATE_DEGRADED_CARRIER = LINK_OPERSTATE_DEGRADED_CARRIER,
        LINK_CARRIER_STATE_CARRIER          = LINK_OPERSTATE_CARRIER,
        LINK_CARRIER_STATE_ENSLAVED         = LINK_OPERSTATE_ENSLAVED,
        _LINK_CARRIER_STATE_MAX,
        _LINK_CARRIER_STATE_INVALID = -EINVAL,
} LinkCarrierState;

typedef enum LinkAddressState {
        LINK_ADDRESS_STATE_OFF,
        LINK_ADDRESS_STATE_DEGRADED,
        LINK_ADDRESS_STATE_ROUTABLE,
        _LINK_ADDRESS_STATE_MAX,
        _LINK_ADDRESS_STATE_INVALID = -EINVAL,
} LinkAddressState;

typedef enum LinkOnlineState {
        LINK_ONLINE_STATE_OFFLINE,
        LINK_ONLINE_STATE_PARTIAL,
        LINK_ONLINE_STATE_ONLINE,
        _LINK_ONLINE_STATE_MAX,
        _LINK_ONLINE_STATE_INVALID = -EINVAL,
} LinkOnlineState;

const char* link_operstate_to_string(LinkOperationalState s) _const_;
LinkOperationalState link_operstate_from_string(const char *s) _pure_;

const char* link_carrier_state_to_string(LinkCarrierState s) _const_;
LinkCarrierState link_carrier_state_from_string(const char *s) _pure_;

const char* link_required_address_family_to_string(AddressFamily s) _const_;
AddressFamily link_required_address_family_from_string(const char *s) _pure_;

const char* link_address_state_to_string(LinkAddressState s) _const_;
LinkAddressState link_address_state_from_string(const char *s) _pure_;

const char* link_online_state_to_string(LinkOnlineState s) _const_;
LinkOnlineState link_online_state_from_string(const char *s) _pure_;

typedef struct LinkOperationalStateRange {
        LinkOperationalState min;
        LinkOperationalState max;
} LinkOperationalStateRange;

#define LINK_OPERSTATE_RANGE_DEFAULT            \
        (const LinkOperationalStateRange) {     \
                .min = LINK_OPERSTATE_DEGRADED, \
                .max = LINK_OPERSTATE_ROUTABLE, \
        }

#define LINK_OPERSTATE_RANGE_INVALID            \
        (const LinkOperationalStateRange) {     \
                .min = _LINK_OPERSTATE_INVALID, \
                .max = _LINK_OPERSTATE_INVALID, \
        }

int parse_operational_state_range(const char *s, LinkOperationalStateRange *ret);
int network_link_get_operational_state(int ifindex, LinkOperationalState *ret);

static inline bool operational_state_is_valid(LinkOperationalState s) {
        return s >= 0 && s < _LINK_OPERSTATE_MAX;
}
static inline bool operational_state_range_is_valid(const LinkOperationalStateRange *range) {
        return range &&
                operational_state_is_valid(range->min) &&
                operational_state_is_valid(range->max) &&
                range->min <= range->max;
}
static inline bool operational_state_is_in_range(LinkOperationalState s, const LinkOperationalStateRange *range) {
        return range && range->min <= s && s <= range->max;
}
