/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "macro.h"
#include "sparse-endian.h"

struct DHCP6Message {
        union {
                struct {
                        uint8_t type;
                        uint8_t _pad[3];
                } _packed_;
                be32_t transaction_id;
        };
        uint8_t options[];
} _packed_;

typedef struct DHCP6Message DHCP6Message;

#define DHCP6_MIN_OPTIONS_SIZE \
        1280 - sizeof(struct ip6_hdr) - sizeof(struct udphdr)

#define IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS                 \
        ((const struct in6_addr) { { {                              \
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     \
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,     \
         } } } )

enum {
        DHCP6_PORT_SERVER                       = 547,
        DHCP6_PORT_CLIENT                       = 546,
};

#define DHCP6_INF_TIMEOUT                       (1 * USEC_PER_SEC)
#define DHCP6_INF_MAX_RT                        (120 * USEC_PER_SEC)
#define DHCP6_SOL_MAX_DELAY                     (1 * USEC_PER_SEC)
#define DHCP6_SOL_TIMEOUT                       (1 * USEC_PER_SEC)
#define DHCP6_SOL_MAX_RT                        (120 * USEC_PER_SEC)
#define DHCP6_REQ_TIMEOUT                       (1 * USEC_PER_SEC)
#define DHCP6_REQ_MAX_RT                        (120 * USEC_PER_SEC)
#define DHCP6_REQ_MAX_RC                        10
#define DHCP6_REN_TIMEOUT                       (10 * USEC_PER_SEC)
#define DHCP6_REN_MAX_RT                        (600 * USEC_PER_SEC)
#define DHCP6_REB_TIMEOUT                       (10 * USEC_PER_SEC)
#define DHCP6_REB_MAX_RT                        (600 * USEC_PER_SEC)

typedef enum DHCP6State {
        DHCP6_STATE_STOPPED,
        DHCP6_STATE_INFORMATION_REQUEST,
        DHCP6_STATE_SOLICITATION,
        DHCP6_STATE_REQUEST,
        DHCP6_STATE_BOUND,
        DHCP6_STATE_RENEW,
        DHCP6_STATE_REBIND,
        DHCP6_STATE_STOPPING,
        _DHCP6_STATE_MAX,
        _DHCP6_STATE_INVALID = -EINVAL,
} DHCP6State;

/* https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-1 */
typedef enum DHCP6MessageType {
        DHCP6_MESSAGE_SOLICIT                   = 1,  /* RFC 8415 */
        DHCP6_MESSAGE_ADVERTISE                 = 2,  /* RFC 8415 */
        DHCP6_MESSAGE_REQUEST                   = 3,  /* RFC 8415 */
        DHCP6_MESSAGE_CONFIRM                   = 4,  /* RFC 8415 */
        DHCP6_MESSAGE_RENEW                     = 5,  /* RFC 8415 */
        DHCP6_MESSAGE_REBIND                    = 6,  /* RFC 8415 */
        DHCP6_MESSAGE_REPLY                     = 7,  /* RFC 8415 */
        DHCP6_MESSAGE_RELEASE                   = 8,  /* RFC 8415 */
        DHCP6_MESSAGE_DECLINE                   = 9,  /* RFC 8415 */
        DHCP6_MESSAGE_RECONFIGURE               = 10, /* RFC 8415 */
        DHCP6_MESSAGE_INFORMATION_REQUEST       = 11, /* RFC 8415 */
        DHCP6_MESSAGE_RELAY_FORWARD             = 12, /* RFC 8415 */
        DHCP6_MESSAGE_RELAY_REPLY               = 13, /* RFC 8415 */
        DHCP6_MESSAGE_LEASE_QUERY               = 14, /* RFC 5007 */
        DHCP6_MESSAGE_LEASE_QUERY_REPLY         = 15, /* RFC 5007 */
        DHCP6_MESSAGE_LEASE_QUERY_DONE          = 16, /* RFC 5460 */
        DHCP6_MESSAGE_LEASE_QUERY_DATA          = 17, /* RFC 5460 */
        DHCP6_MESSAGE_RECONFIGURE_REQUEST       = 18, /* RFC 6977 */
        DHCP6_MESSAGE_RECONFIGURE_REPLY         = 19, /* RFC 6977 */
        DHCP6_MESSAGE_DHCPV4_QUERY              = 20, /* RFC 7341 */
        DHCP6_MESSAGE_DHCPV4_RESPONSE           = 21, /* RFC 7341 */
        DHCP6_MESSAGE_ACTIVE_LEASE_QUERY        = 22, /* RFC 7653 */
        DHCP6_MESSAGE_START_TLS                 = 23, /* RFC 7653 */
        DHCP6_MESSAGE_BINDING_UPDATE            = 24, /* RFC 8156 */
        DHCP6_MESSAGE_BINDING_REPLY             = 25, /* RFC 8156 */
        DHCP6_MESSAGE_POOL_REQUEST              = 26, /* RFC 8156 */
        DHCP6_MESSAGE_POOL_RESPONSE             = 27, /* RFC 8156 */
        DHCP6_MESSAGE_UPDATE_REQUEST            = 28, /* RFC 8156 */
        DHCP6_MESSAGE_UPDATE_REQUEST_ALL        = 29, /* RFC 8156 */
        DHCP6_MESSAGE_UPDATE_DONE               = 30, /* RFC 8156 */
        DHCP6_MESSAGE_CONNECT                   = 31, /* RFC 8156 */
        DHCP6_MESSAGE_CONNECT_REPLY             = 32, /* RFC 8156 */
        DHCP6_MESSAGE_DISCONNECT                = 33, /* RFC 8156 */
        DHCP6_MESSAGE_STATE                     = 34, /* RFC 8156 */
        DHCP6_MESSAGE_CONTACT                   = 35, /* RFC 8156 */
        _DHCP6_MESSAGE_TYPE_MAX,
        _DHCP6_MESSAGE_TYPE_INVALID             = -EINVAL,
} DHCP6MessageType;

typedef enum DHCP6NTPSubOption {
        DHCP6_NTP_SUBOPTION_SRV_ADDR            = 1,
        DHCP6_NTP_SUBOPTION_MC_ADDR             = 2,
        DHCP6_NTP_SUBOPTION_SRV_FQDN            = 3,
        _DHCP6_NTP_SUBOPTION_MAX,
        _DHCP6_NTP_SUBOPTION_INVALID            = -EINVAL,
} DHCP6NTPSubOption;

/*
 * RFC 8415, RFC 5007 and RFC 7653 status codes:
 * https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-5
 */
typedef enum DHCP6Status {
        DHCP6_STATUS_SUCCESS                      = 0,
        DHCP6_STATUS_UNSPEC_FAIL                  = 1,
        DHCP6_STATUS_NO_ADDRS_AVAIL               = 2,
        DHCP6_STATUS_NO_BINDING                   = 3,
        DHCP6_STATUS_NOT_ON_LINK                  = 4,
        DHCP6_STATUS_USE_MULTICAST                = 5,
        DHCP6_STATUS_NO_PREFIX_AVAIL              = 6,
        DHCP6_STATUS_UNKNOWN_QUERY_TYPE           = 7,
        DHCP6_STATUS_MALFORMED_QUERY              = 8,
        DHCP6_STATUS_NOT_CONFIGURED               = 9,
        DHCP6_STATUS_NOT_ALLOWED                  = 10,
        DHCP6_STATUS_QUERY_TERMINATED             = 11,
        DHCP6_STATUS_DATA_MISSING                 = 12,
        DHCP6_STATUS_CATCHUP_COMPLETE             = 13,
        DHCP6_STATUS_NOT_SUPPORTED                = 14,
        DHCP6_STATUS_TLS_CONNECTION_REFUSED       = 15,
        DHCP6_STATUS_ADDRESS_IN_USE               = 16,
        DHCP6_STATUS_CONFIGURATION_CONFLICT       = 17,
        DHCP6_STATUS_MISSING_BINDING_INFORMATION  = 18,
        DHCP6_STATUS_OUTDATED_BINDING_INFORMATION = 19,
        DHCP6_STATUS_SERVER_SHUTTING_DOWN         = 20,
        DHCP6_STATUS_DNS_UPDATE_NOT_SUPPORTED     = 21,
        DHCP6_STATUS_EXCESSIVE_TIME_SKEW          = 22,
        _DHCP6_STATUS_MAX,
        _DHCP6_STATUS_INVALID                     = -EINVAL,
} DHCP6Status;

typedef enum DHCP6FQDNFlag {
        DHCP6_FQDN_FLAG_S = 1 << 0,
        DHCP6_FQDN_FLAG_O = 1 << 1,
        DHCP6_FQDN_FLAG_N = 1 << 2,
} DHCP6FQDNFlag;

const char* dhcp6_state_to_string(DHCP6State s) _const_;
const char* dhcp6_message_type_to_string(DHCP6MessageType s) _const_;
DHCP6MessageType dhcp6_message_type_from_string(const char *s) _pure_;
const char* dhcp6_message_status_to_string(DHCP6Status s) _const_;
DHCP6Status dhcp6_message_status_from_string(const char *s) _pure_;
int dhcp6_message_status_to_errno(DHCP6Status s);
