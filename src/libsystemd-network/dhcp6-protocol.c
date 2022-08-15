/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp6-protocol.h"
#include "string-table.h"

static const char * const dhcp6_state_table[_DHCP6_STATE_MAX] = {
        [DHCP6_STATE_STOPPED]             = "stopped",
        [DHCP6_STATE_INFORMATION_REQUEST] = "information-request",
        [DHCP6_STATE_SOLICITATION]        = "solicitation",
        [DHCP6_STATE_REQUEST]             = "request",
        [DHCP6_STATE_BOUND]               = "bound",
        [DHCP6_STATE_RENEW]               = "renew",
        [DHCP6_STATE_REBIND]              = "rebind",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(dhcp6_state, DHCP6State);

static const char * const dhcp6_message_type_table[_DHCP6_MESSAGE_TYPE_MAX] = {
        [DHCP6_MESSAGE_SOLICIT]             = "Solicit",
        [DHCP6_MESSAGE_ADVERTISE]           = "Advertise",
        [DHCP6_MESSAGE_REQUEST]             = "Request",
        [DHCP6_MESSAGE_CONFIRM]             = "Confirm",
        [DHCP6_MESSAGE_RENEW]               = "Renew",
        [DHCP6_MESSAGE_REBIND]              = "Rebind",
        [DHCP6_MESSAGE_REPLY]               = "Reply",
        [DHCP6_MESSAGE_RELEASE]             = "Release",
        [DHCP6_MESSAGE_DECLINE]             = "Decline",
        [DHCP6_MESSAGE_RECONFIGURE]         = "Reconfigure",
        [DHCP6_MESSAGE_INFORMATION_REQUEST] = "Information Request",
        [DHCP6_MESSAGE_RELAY_FORWARD]       = "Relay Forward",
        [DHCP6_MESSAGE_RELAY_REPLY]         = "Relay Reply",
        [DHCP6_MESSAGE_LEASE_QUERY]         = "Lease Query",
        [DHCP6_MESSAGE_LEASE_QUERY_REPLY]   = "Lease Query Reply",
        [DHCP6_MESSAGE_LEASE_QUERY_DONE]    = "Lease Query Done",
        [DHCP6_MESSAGE_LEASE_QUERY_DATA]    = "Lease Query Data",
        [DHCP6_MESSAGE_RECONFIGURE_REQUEST] = "Reconfigure Request",
        [DHCP6_MESSAGE_RECONFIGURE_REPLY]   = "Reconfigure Reply",
        [DHCP6_MESSAGE_DHCPV4_QUERY]        = "DHCPv4 Query",
        [DHCP6_MESSAGE_DHCPV4_RESPONSE]     = "DHCPv4 Response",
        [DHCP6_MESSAGE_ACTIVE_LEASE_QUERY]  = "Active Lease Query",
        [DHCP6_MESSAGE_START_TLS]           = "Start TLS",
        [DHCP6_MESSAGE_BINDING_UPDATE]      = "Binding Update",
        [DHCP6_MESSAGE_BINDING_REPLY]       = "Binding Reply",
        [DHCP6_MESSAGE_POOL_REQUEST]        = "Pool Request",
        [DHCP6_MESSAGE_POOL_RESPONSE]       = "Pool Response",
        [DHCP6_MESSAGE_UPDATE_REQUEST]      = "Update Request",
        [DHCP6_MESSAGE_UPDATE_REQUEST_ALL]  = "Update Request All",
        [DHCP6_MESSAGE_UPDATE_DONE]         = "Update Done",
        [DHCP6_MESSAGE_CONNECT]             = "Connect",
        [DHCP6_MESSAGE_CONNECT_REPLY]       = "Connect Reply",
        [DHCP6_MESSAGE_DISCONNECT]          = "Disconnect",
        [DHCP6_MESSAGE_STATE]               = "State",
        [DHCP6_MESSAGE_CONTACT]             = "Contact",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_type, DHCP6MessageType);

static const char * const dhcp6_message_status_table[_DHCP6_STATUS_MAX] = {
        [DHCP6_STATUS_SUCCESS]                      = "Success",
        [DHCP6_STATUS_UNSPEC_FAIL]                  = "Unspecified failure",
        [DHCP6_STATUS_NO_ADDRS_AVAIL]               = "No addresses available",
        [DHCP6_STATUS_NO_BINDING]                   = "Binding unavailable",
        [DHCP6_STATUS_NOT_ON_LINK]                  = "Not on link",
        [DHCP6_STATUS_USE_MULTICAST]                = "Use multicast",
        [DHCP6_STATUS_NO_PREFIX_AVAIL]              = "No prefix available",
        [DHCP6_STATUS_UNKNOWN_QUERY_TYPE]           = "Unknown query type",
        [DHCP6_STATUS_MALFORMED_QUERY]              = "Malformed query",
        [DHCP6_STATUS_NOT_CONFIGURED]               = "Not configured",
        [DHCP6_STATUS_NOT_ALLOWED]                  = "Not allowed",
        [DHCP6_STATUS_QUERY_TERMINATED]             = "Query terminated",
        [DHCP6_STATUS_DATA_MISSING]                 = "Data missing",
        [DHCP6_STATUS_CATCHUP_COMPLETE]             = "Catch up complete",
        [DHCP6_STATUS_NOT_SUPPORTED]                = "Not supported",
        [DHCP6_STATUS_TLS_CONNECTION_REFUSED]       = "TLS connection refused",
        [DHCP6_STATUS_ADDRESS_IN_USE]               = "Address in use",
        [DHCP6_STATUS_CONFIGURATION_CONFLICT]       = "Configuration conflict",
        [DHCP6_STATUS_MISSING_BINDING_INFORMATION]  = "Missing binding information",
        [DHCP6_STATUS_OUTDATED_BINDING_INFORMATION] = "Outdated binding information",
        [DHCP6_STATUS_SERVER_SHUTTING_DOWN]         = "Server shutting down",
        [DHCP6_STATUS_DNS_UPDATE_NOT_SUPPORTED]     = "DNS update not supported",
        [DHCP6_STATUS_EXCESSIVE_TIME_SKEW]          = "Excessive time skew",
};

DEFINE_STRING_TABLE_LOOKUP(dhcp6_message_status, DHCP6Status);

int dhcp6_message_status_to_errno(DHCP6Status s) {
        switch (s) {
        case DHCP6_STATUS_SUCCESS:
                return 0;
        case DHCP6_STATUS_NO_BINDING:
                return -EADDRNOTAVAIL;
        default:
                return -EINVAL;
        }
}
