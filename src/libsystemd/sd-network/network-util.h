/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-device.h"
#include "sd-network.h"

#include "macro.h"

bool network_is_online(void);

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

const char* link_operstate_to_string(LinkOperationalState s) _const_;
LinkOperationalState link_operstate_from_string(const char *s) _pure_;

const char* link_carrier_state_to_string(LinkCarrierState s) _const_;
LinkCarrierState link_carrier_state_from_string(const char *s) _pure_;

const char* link_address_state_to_string(LinkAddressState s) _const_;
LinkAddressState link_address_state_from_string(const char *s) _pure_;

typedef struct LinkOperationalStateRange {
        LinkOperationalState min;
        LinkOperationalState max;
} LinkOperationalStateRange;

#define LINK_OPERSTATE_RANGE_DEFAULT (LinkOperationalStateRange) { LINK_OPERSTATE_DEGRADED, \
                                                                   LINK_OPERSTATE_ROUTABLE }

int parse_operational_state_range(const char *str, LinkOperationalStateRange *out);

char *link_get_type_string(sd_device *device, unsigned short iftype);
int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *result);
const char *net_get_name_persistent(sd_device *device);
