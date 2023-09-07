/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-protocol.h"
#include "string-table.h"

static const char* const dhcp_state_table[_DHCP_STATE_MAX] = {
        [DHCP_STATE_STOPPED]              = "stopped",
        [DHCP_STATE_INIT]                 = "initialization",
        [DHCP_STATE_SELECTING]            = "selecting",
        [DHCP_STATE_INIT_REBOOT]          = "init-reboot",
        [DHCP_STATE_REBOOTING]            = "rebooting",
        [DHCP_STATE_REQUESTING]           = "requesting",
        [DHCP_STATE_BOUND]                = "bound",
        [DHCP_STATE_RENEWING]             = "renewing",
        [DHCP_STATE_REBINDING]            = "rebinding",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(dhcp_state, DHCPState);
