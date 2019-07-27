/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-network.h"

#include "macro.h"

bool network_is_online(void);

typedef enum LinkOperationalState {
        LINK_OPERSTATE_OFF,
        LINK_OPERSTATE_NO_CARRIER,
        LINK_OPERSTATE_DORMANT,
        LINK_OPERSTATE_DEGRADED_CARRIER,
        LINK_OPERSTATE_CARRIER,
        LINK_OPERSTATE_DEGRADED,
        LINK_OPERSTATE_ENSLAVED,
        LINK_OPERSTATE_ROUTABLE,
        _LINK_OPERSTATE_MAX,
        _LINK_OPERSTATE_INVALID = -1
} LinkOperationalState;

typedef enum LinkCarrierState {
        LINK_CARRIER_STATE_OFF              = LINK_OPERSTATE_OFF,
        LINK_CARRIER_STATE_NO_CARRIER       = LINK_OPERSTATE_NO_CARRIER,
        LINK_CARRIER_STATE_DORMANT          = LINK_OPERSTATE_DORMANT,
        LINK_CARRIER_STATE_DEGRADED_CARRIER = LINK_OPERSTATE_DEGRADED_CARRIER,
        LINK_CARRIER_STATE_CARRIER          = LINK_OPERSTATE_CARRIER,
        LINK_CARRIER_STATE_ENSLAVED         = LINK_OPERSTATE_ENSLAVED,
        _LINK_CARRIER_STATE_MAX,
        _LINK_CARRIER_STATE_INVALID = -1
} LinkCarrierState;

typedef enum LinkAddressState {
        LINK_ADDRESS_STATE_OFF,
        LINK_ADDRESS_STATE_DEGRADED,
        LINK_ADDRESS_STATE_ROUTABLE,
        _LINK_ADDRESS_STATE_MAX,
        _LINK_ADDRESS_STATE_INVALID = -1
} LinkAddressState;

const char* link_operstate_to_string(LinkOperationalState s) _const_;
LinkOperationalState link_operstate_from_string(const char *s) _pure_;

const char* link_carrier_state_to_string(LinkCarrierState s) _const_;
LinkCarrierState link_carrier_state_from_string(const char *s) _pure_;

const char* link_address_state_to_string(LinkAddressState s) _const_;
LinkAddressState link_address_state_from_string(const char *s) _pure_;
