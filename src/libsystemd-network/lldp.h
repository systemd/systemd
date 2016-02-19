#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

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

#define LLDP_MULTICAST_ADDR     { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }

/* IEEE 802.3AB Clause 9: TLV Types */
enum {
        LLDP_TYPE_END                  =   0,
        LLDP_TYPE_CHASSIS_ID           =   1,
        LLDP_TYPE_PORT_ID              =   2,
        LLDP_TYPE_TTL                  =   3,
        LLDP_TYPE_PORT_DESCRIPTION     =   4,
        LLDP_TYPE_SYSTEM_NAME          =   5,
        LLDP_TYPE_SYSTEM_DESCRIPTION   =   6,
        LLDP_TYPE_SYSTEM_CAPABILITIES  =   7,
        LLDP_TYPE_MGMT_ADDRESS         =   8,
        LLDP_TYPE_PRIVATE              =   127,
};

/* IEEE 802.3AB Clause 9.5.2: Chassis subtypes */
enum {
        LLDP_CHASSIS_SUBTYPE_RESERVED            = 0,
        LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT   = 1,
        LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS     = 2,
        LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT      = 3,
        LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS         = 4,
        LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS     = 5,
        LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME      = 6,
        LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED    = 7,
};

/* IEEE 802.3AB Clause 9.5.3: Port subtype */
enum {
        LLDP_PORT_SUBTYPE_RESERVED           = 0,
        LLDP_PORT_SUBTYPE_INTERFACE_ALIAS    = 1,
        LLDP_PORT_SUBTYPE_PORT_COMPONENT     = 2,
        LLDP_PORT_SUBTYPE_MAC_ADDRESS        = 3,
        LLDP_PORT_SUBTYPE_NETWORK_ADDRESS    = 4,
        LLDP_PORT_SUBTYPE_INTERFACE_NAME     = 5,
        LLDP_PORT_SUBTYPE_AGENT_CIRCUIT_ID   = 6,
        LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED   = 7,
};

enum {
        LLDP_SYSTEM_CAPABILITIES_OTHER        = 1 << 0,
        LLDP_SYSTEM_CAPABILITIES_REPEATER     = 1 << 1,
        LLDP_SYSTEM_CAPABILITIES_BRIDGE       = 1 << 2,
        LLDP_SYSTEM_CAPABILITIES_WLAN_AP      = 1 << 3,
        LLDP_SYSTEM_CAPABILITIES_ROUTER       = 1 << 4,
        LLDP_SYSTEM_CAPABILITIES_PHONE        = 1 << 5,
        LLDP_SYSTEM_CAPABILITIES_DOCSIS       = 1 << 6,
        LLDP_SYSTEM_CAPABILITIES_STATION      = 1 << 7,
        LLDP_SYSTEM_CAPABILITIES_CVLAN        = 1 << 8,
        LLDP_SYSTEM_CAPABILITIES_SVLAN        = 1 << 9,
        LLDP_SYSTEM_CAPABILITIES_TPMR         = 1 << 10,
};

#define _LLDP_SYSTEM_CAPABILITIES_ALL ((uint16_t) -1)

#define _LLDP_SYSTEM_CAPABILITIES_ALL_ROUTERS                           \
        ((uint16_t)                                                     \
         (LLDP_SYSTEM_CAPABILITIES_REPEATER|                            \
          LLDP_SYSTEM_CAPABILITIES_BRIDGE|                              \
          LLDP_SYSTEM_CAPABILITIES_WLAN_AP|                             \
          LLDP_SYSTEM_CAPABILITIES_ROUTER|                              \
          LLDP_SYSTEM_CAPABILITIES_DOCSIS|                              \
          LLDP_SYSTEM_CAPABILITIES_CVLAN|                               \
          LLDP_SYSTEM_CAPABILITIES_SVLAN|                               \
          LLDP_SYSTEM_CAPABILITIES_TPMR))


#define LLDP_OUI_802_1 (uint8_t[]) { 0x00, 0x80, 0xc2 }
#define LLDP_OUI_802_3 (uint8_t[]) { 0x00, 0x12, 0x0f }

enum {
        LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID            = 1,
        LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID   = 2,
        LLDP_OUI_802_1_SUBTYPE_VLAN_NAME               = 3,
        LLDP_OUI_802_1_SUBTYPE_PROTOCOL_IDENTITY       = 4,
        LLDP_OUI_802_1_SUBTYPE_VID_USAGE_DIGEST        = 5,
        LLDP_OUI_802_1_SUBTYPE_MANAGEMENT_VID          = 6,
        LLDP_OUI_802_1_SUBTYPE_LINK_AGGREGATION        = 7,
};
