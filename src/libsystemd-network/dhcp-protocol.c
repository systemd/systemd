/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-protocol.h"
#include "string-table.h"

static const char * const bootp_message_type_table[_BOOTP_MESSAGE_TYPE_MAX] = {
        [BOOTREQUEST]           = "BOOTREQUEST",
        [BOOTREPLY]             = "BOOTREPLY",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(bootp_message_type, BOOTPMessageType);

static const char * const dhcp_message_type_table[_DHCP_MESSAGE_TYPE_MAX] = {
        [DHCP_DISCOVER]         = "DISCOVER",
        [DHCP_OFFER]            = "OFFER",
        [DHCP_REQUEST]          = "REQUEST",
        [DHCP_DECLINE]          = "DECLINE",
        [DHCP_ACK]              = "ACK",
        [DHCP_NAK]              = "NAK",
        [DHCP_RELEASE]          = "RELEASE",
        [DHCP_INFORM]           = "INFORM",
        [DHCP_FORCERENEW]       = "FORCERENEW",
        [DHCP_LEASEQUERY]       = "LEASEQUERY",
        [DHCP_LEASEUNASSIGNED]  = "LEASEUNASSIGNED",
        [DHCP_LEASEUNKNOWN]     = "LEASEUNKNOWN",
        [DHCP_LEASEACTIVE]      = "LEASEACTIVE",
        [DHCP_BULKLEASEQUERY]   = "BULKLEASEQUERY",
        [DHCP_LEASEQUERYDONE]   = "LEASEQUERYDONE",
        [DHCP_ACTIVELEASEQUERY] = "ACTIVELEASEQUERY",
        [DHCP_LEASEQUERYSTATUS] = "LEASEQUERYSTATUS",
        [DHCP_TLS]              = "TLS",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(dhcp_message_type, DHCPMessageType);
