/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>

#include "macro.h"
#include "sparse-endian.h"

struct DHCPMessage {
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
        uint8_t options[0];
} _packed_;

typedef struct DHCPMessage DHCPMessage;

struct DHCPPacket {
        struct iphdr ip;
        struct udphdr udp;
        DHCPMessage dhcp;
} _packed_;

typedef struct DHCPPacket DHCPPacket;

#define DHCP_IP_SIZE            (int32_t)(sizeof(struct iphdr))
#define DHCP_IP_UDP_SIZE        (int32_t)(sizeof(struct udphdr) + DHCP_IP_SIZE)
#define DHCP_HEADER_SIZE        (int32_t)(sizeof(DHCPMessage))
#define DHCP_MIN_MESSAGE_SIZE   576 /* the minimum internet hosts must be able to receive, see RFC 2132 Section 9.10 */
#define DHCP_MIN_OPTIONS_SIZE   (DHCP_MIN_MESSAGE_SIZE - DHCP_HEADER_SIZE)
#define DHCP_MIN_PACKET_SIZE    (DHCP_MIN_MESSAGE_SIZE + DHCP_IP_UDP_SIZE)
#define DHCP_MAGIC_COOKIE       (uint32_t)(0x63825363)

enum {
        DHCP_PORT_SERVER                        = 67,
        DHCP_PORT_CLIENT                        = 68,
};

enum DHCPState {
        DHCP_STATE_INIT                         = 0,
        DHCP_STATE_SELECTING                    = 1,
        DHCP_STATE_INIT_REBOOT                  = 2,
        DHCP_STATE_REBOOTING                    = 3,
        DHCP_STATE_REQUESTING                   = 4,
        DHCP_STATE_BOUND                        = 5,
        DHCP_STATE_RENEWING                     = 6,
        DHCP_STATE_REBINDING                    = 7,
        DHCP_STATE_STOPPED                      = 8,
};

typedef enum DHCPState DHCPState;

enum {
        BOOTREQUEST                             = 1,
        BOOTREPLY                               = 2,
};

enum {
        DHCP_DISCOVER                           = 1,  /* [RFC2132] */
        DHCP_OFFER                              = 2,  /* [RFC2132] */
        DHCP_REQUEST                            = 3,  /* [RFC2132] */
        DHCP_DECLINE                            = 4,  /* [RFC2132] */
        DHCP_ACK                                = 5,  /* [RFC2132] */
        DHCP_NAK                                = 6,  /* [RFC2132] */
        DHCP_RELEASE                            = 7,  /* [RFC2132] */
        DHCP_INFORM                             = 8,  /* [RFC2132] */
        DHCP_FORCERENEW                         = 9,  /* [RFC3203] */
        DHCPLEASEQUERY                          = 10, /* [RFC4388] */
        DHCPLEASEUNASSIGNED                     = 11, /* [RFC4388] */
        DHCPLEASEUNKNOWN                        = 12, /* [RFC4388] */
        DHCPLEASEACTIVE                         = 13, /* [RFC4388] */
        DHCPBULKLEASEQUERY                      = 14, /* [RFC6926] */
        DHCPLEASEQUERYDONE                      = 15, /* [RFC6926] */
        DHCPACTIVELEASEQUERY                    = 16, /* [RFC7724] */
        DHCPLEASEQUERYSTATUS                    = 17, /* [RFC7724] */
        DHCPTLS                                 = 18, /* [RFC7724] */
};

enum {
        DHCP_OVERLOAD_FILE                      = 1,
        DHCP_OVERLOAD_SNAME                     = 2,
};

#define DHCP_MAX_FQDN_LENGTH 255

enum {
        DHCP_FQDN_FLAG_S = (1 << 0),
        DHCP_FQDN_FLAG_O = (1 << 1),
        DHCP_FQDN_FLAG_E = (1 << 2),
        DHCP_FQDN_FLAG_N = (1 << 3),
};
