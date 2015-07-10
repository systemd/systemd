/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/udp.h>
#include <netinet/ip.h>
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
#define DHCP_MESSAGE_SIZE       (int32_t)(sizeof(DHCPMessage))
#define DHCP_DEFAULT_MIN_SIZE   576 /* the minimum internet hosts must be able to receive */
#define DHCP_MIN_OPTIONS_SIZE   DHCP_DEFAULT_MIN_SIZE - DHCP_IP_UDP_SIZE - DHCP_MESSAGE_SIZE
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
        DHCP_DISCOVER                           = 1,
        DHCP_OFFER                              = 2,
        DHCP_REQUEST                            = 3,
        DHCP_DECLINE                            = 4,
        DHCP_ACK                                = 5,
        DHCP_NAK                                = 6,
        DHCP_RELEASE                            = 7,
        DHCP_INFORM                             = 8,
        DHCP_FORCERENEW                         = 9,
};

enum {
        DHCP_OVERLOAD_FILE                      = 1,
        DHCP_OVERLOAD_SNAME                     = 2,
};

enum {
        DHCP_OPTION_PAD                         = 0,
        DHCP_OPTION_SUBNET_MASK                 = 1,
        DHCP_OPTION_TIME_OFFSET                 = 2,
        DHCP_OPTION_ROUTER                      = 3,
        DHCP_OPTION_DOMAIN_NAME_SERVER          = 6,
        DHCP_OPTION_HOST_NAME                   = 12,
        DHCP_OPTION_BOOT_FILE_SIZE              = 13,
        DHCP_OPTION_DOMAIN_NAME                 = 15,
        DHCP_OPTION_ROOT_PATH                   = 17,
        DHCP_OPTION_ENABLE_IP_FORWARDING        = 19,
        DHCP_OPTION_ENABLE_IP_FORWARDING_NL     = 20,
        DHCP_OPTION_POLICY_FILTER               = 21,
        DHCP_OPTION_INTERFACE_MDR               = 22,
        DHCP_OPTION_INTERFACE_TTL               = 23,
        DHCP_OPTION_INTERFACE_MTU_AGING_TIMEOUT = 24,
        DHCP_OPTION_INTERFACE_MTU               = 26,
        DHCP_OPTION_BROADCAST                   = 28,
        DHCP_OPTION_STATIC_ROUTE                = 33,
        DHCP_OPTION_NTP_SERVER                  = 42,
        DHCP_OPTION_VENDOR_SPECIFIC             = 43,
        DHCP_OPTION_REQUESTED_IP_ADDRESS        = 50,
        DHCP_OPTION_IP_ADDRESS_LEASE_TIME       = 51,
        DHCP_OPTION_OVERLOAD                    = 52,
        DHCP_OPTION_MESSAGE_TYPE                = 53,
        DHCP_OPTION_SERVER_IDENTIFIER           = 54,
        DHCP_OPTION_PARAMETER_REQUEST_LIST      = 55,
        DHCP_OPTION_MAXIMUM_MESSAGE_SIZE        = 57,
        DHCP_OPTION_RENEWAL_T1_TIME             = 58,
        DHCP_OPTION_REBINDING_T2_TIME           = 59,
        DHCP_OPTION_VENDOR_CLASS_IDENTIFIER     = 60,
        DHCP_OPTION_CLIENT_IDENTIFIER           = 61,
        DHCP_OPTION_CLASSLESS_STATIC_ROUTE      = 121,
        DHCP_OPTION_END                         = 255,
};
