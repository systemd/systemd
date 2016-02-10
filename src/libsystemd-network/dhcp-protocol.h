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

#define DHCP_MAX_FQDN_LENGTH 255

enum {
        DHCP_FQDN_FLAG_S = (1 << 0),
        DHCP_FQDN_FLAG_O = (1 << 1),
        DHCP_FQDN_FLAG_E = (1 << 2),
        DHCP_FQDN_FLAG_N = (1 << 3),
};
