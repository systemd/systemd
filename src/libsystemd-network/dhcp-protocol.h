/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include "sd-dhcp-protocol.h"  /* IWYU pragma: export */

#include "sd-forward.h"
#include "sparse-endian.h"
#include "time-util.h"

/* RFC 8925 - IPv6-Only Preferred Option for DHCPv4 3.4.
 * MIN_V6ONLY_WAIT: The lower boundary for V6ONLY_WAIT. Value: 300 seconds */
#define MIN_V6ONLY_WAIT_USEC (300U * USEC_PER_SEC)

struct DHCPMessageHeader {
        uint8_t op;
        uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        be32_t xid;
        be16_t secs;
        be16_t flags;
        be32_t ciaddr;
        be32_t yiaddr;
        be32_t siaddr;
        be32_t giaddr;
        uint8_t chaddr[16];
        uint8_t sname[64];
        uint8_t file[128];
        be32_t magic;
} _packed_;

typedef struct DHCPMessageHeader DHCPMessageHeader;

#define DHCP_MAGIC_COOKIE       (uint32_t)(0x63825363)

/* The size of BOOTP message. The BOOTP message does not have the magic field, but has the 64-byte
 * vendor-specific area. */
#define BOOTP_MESSAGE_SIZE (offsetof(DHCPMessageHeader, magic) + 64)

enum {
        DHCP_PORT_SERVER                        = 67,
        DHCP_PORT_CLIENT                        = 68,
};

typedef enum {
        BOOTREQUEST                             = 1,
        BOOTREPLY                               = 2,
        _BOOTP_MESSAGE_TYPE_MAX,
        _BOOTP_MESSAGE_TYPE_INVALID             = -EINVAL,
} BOOTPMessageType;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(bootp_message_type, BOOTPMessageType);

typedef enum {
        DHCP_DISCOVER                           = 1,  /* [RFC2132] */
        DHCP_OFFER                              = 2,  /* [RFC2132] */
        DHCP_REQUEST                            = 3,  /* [RFC2132] */
        DHCP_DECLINE                            = 4,  /* [RFC2132] */
        DHCP_ACK                                = 5,  /* [RFC2132] */
        DHCP_NAK                                = 6,  /* [RFC2132] */
        DHCP_RELEASE                            = 7,  /* [RFC2132] */
        DHCP_INFORM                             = 8,  /* [RFC2132] */
        DHCP_FORCERENEW                         = 9,  /* [RFC3203] */
        DHCP_LEASEQUERY                         = 10, /* [RFC4388] */
        DHCP_LEASEUNASSIGNED                    = 11, /* [RFC4388] */
        DHCP_LEASEUNKNOWN                       = 12, /* [RFC4388] */
        DHCP_LEASEACTIVE                        = 13, /* [RFC4388] */
        DHCP_BULKLEASEQUERY                     = 14, /* [RFC6926] */
        DHCP_LEASEQUERYDONE                     = 15, /* [RFC6926] */
        DHCP_ACTIVELEASEQUERY                   = 16, /* [RFC7724] */
        DHCP_LEASEQUERYSTATUS                   = 17, /* [RFC7724] */
        DHCP_TLS                                = 18, /* [RFC7724] */
        _DHCP_MESSAGE_TYPE_MAX,
        _DHCP_MESSAGE_TYPE_INVALID              = -EINVAL,
} DHCPMessageType;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(dhcp_message_type, DHCPMessageType);

typedef enum {
        DHCP_OVERLOAD_NONE                      = 0,
        DHCP_OVERLOAD_FILE                      = 1 << 0,
        DHCP_OVERLOAD_SNAME                     = 1 << 1,
        _DHCP_OVERLOAD_ALL                      = DHCP_OVERLOAD_FILE | DHCP_OVERLOAD_SNAME,
} DHCPOptionOverload;

#define DHCP_MAX_FQDN_LENGTH 255

enum {
        DHCP_FQDN_FLAG_S = (1 << 0),
        DHCP_FQDN_FLAG_O = (1 << 1),
        DHCP_FQDN_FLAG_E = (1 << 2),
        DHCP_FQDN_FLAG_N = (1 << 3),
};

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(dhcp_option_code, int);
