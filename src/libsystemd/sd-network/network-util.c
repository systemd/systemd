/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fd-util.h"
#include "network-util.h"
#include "string-table.h"
#include "strv.h"

bool network_is_online(void) {
        _cleanup_free_ char *carrier_state = NULL, *addr_state = NULL;
        int r;

        r = sd_network_get_carrier_state(&carrier_state);
        if (r < 0) /* if we don't know anything, we consider the system online */
                return true;

        r = sd_network_get_address_state(&addr_state);
        if (r < 0) /* if we don't know anything, we consider the system online */
                return true;

        if (STR_IN_SET(carrier_state, "degraded-carrier", "carrier") &&
            STR_IN_SET(addr_state, "routable", "degraded"))
                return true;

        return false;
}

static const char* const link_operstate_table[_LINK_OPERSTATE_MAX] = {
        [LINK_OPERSTATE_OFF]              = "off",
        [LINK_OPERSTATE_NO_CARRIER]       = "no-carrier",
        [LINK_OPERSTATE_DORMANT]          = "dormant",
        [LINK_OPERSTATE_DEGRADED_CARRIER] = "degraded-carrier",
        [LINK_OPERSTATE_CARRIER]          = "carrier",
        [LINK_OPERSTATE_DEGRADED]         = "degraded",
        [LINK_OPERSTATE_ENSLAVED]         = "enslaved",
        [LINK_OPERSTATE_ROUTABLE]         = "routable",
};

DEFINE_STRING_TABLE_LOOKUP(link_operstate, LinkOperationalState);

static const char* const link_carrier_state_table[_LINK_CARRIER_STATE_MAX] = {
        [LINK_CARRIER_STATE_OFF]              = "off",
        [LINK_CARRIER_STATE_NO_CARRIER]       = "no-carrier",
        [LINK_CARRIER_STATE_DORMANT]          = "dormant",
        [LINK_CARRIER_STATE_DEGRADED_CARRIER] = "degraded-carrier",
        [LINK_CARRIER_STATE_CARRIER]          = "carrier",
        [LINK_CARRIER_STATE_ENSLAVED]         = "enslaved",
};

DEFINE_STRING_TABLE_LOOKUP(link_carrier_state, LinkCarrierState);

static const char* const link_address_state_table[_LINK_ADDRESS_STATE_MAX] = {
        [LINK_ADDRESS_STATE_OFF]      = "off",
        [LINK_ADDRESS_STATE_DEGRADED] = "degraded",
        [LINK_ADDRESS_STATE_ROUTABLE] = "routable",
};

DEFINE_STRING_TABLE_LOOKUP(link_address_state, LinkAddressState);
