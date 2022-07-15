/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdlldphfoo
#define foosdlldphfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <inttypes.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* IEEE 802.1AB-2009 Clause 8: TLV Types */
enum {
        SD_LLDP_TYPE_END                 = 0,
        SD_LLDP_TYPE_CHASSIS_ID          = 1,
        SD_LLDP_TYPE_PORT_ID             = 2,
        SD_LLDP_TYPE_TTL                 = 3,
        SD_LLDP_TYPE_PORT_DESCRIPTION    = 4,
        SD_LLDP_TYPE_SYSTEM_NAME         = 5,
        SD_LLDP_TYPE_SYSTEM_DESCRIPTION  = 6,
        SD_LLDP_TYPE_SYSTEM_CAPABILITIES = 7,
        SD_LLDP_TYPE_MGMT_ADDRESS        = 8,
        SD_LLDP_TYPE_PRIVATE             = 127
};

/* IEEE 802.1AB-2009 Clause 8.5.2: Chassis subtypes */
enum {
        SD_LLDP_CHASSIS_SUBTYPE_RESERVED            = 0,
        SD_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT   = 1,
        SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS     = 2,
        SD_LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT      = 3,
        SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS         = 4,
        SD_LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS     = 5,
        SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME      = 6,
        SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED    = 7
};

/* IEEE 802.1AB-2009 Clause 8.5.3: Port subtype */
enum {
        SD_LLDP_PORT_SUBTYPE_RESERVED         = 0,
        SD_LLDP_PORT_SUBTYPE_INTERFACE_ALIAS  = 1,
        SD_LLDP_PORT_SUBTYPE_PORT_COMPONENT   = 2,
        SD_LLDP_PORT_SUBTYPE_MAC_ADDRESS      = 3,
        SD_LLDP_PORT_SUBTYPE_NETWORK_ADDRESS  = 4,
        SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME   = 5,
        SD_LLDP_PORT_SUBTYPE_AGENT_CIRCUIT_ID = 6,
        SD_LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED = 7
};

/* IEEE 802.1AB-2009 Clause 8.5.8: System capabilities */
enum {
        SD_LLDP_SYSTEM_CAPABILITIES_OTHER    = 1 << 0,
        SD_LLDP_SYSTEM_CAPABILITIES_REPEATER = 1 << 1,
        SD_LLDP_SYSTEM_CAPABILITIES_BRIDGE   = 1 << 2,
        SD_LLDP_SYSTEM_CAPABILITIES_WLAN_AP  = 1 << 3,
        SD_LLDP_SYSTEM_CAPABILITIES_ROUTER   = 1 << 4,
        SD_LLDP_SYSTEM_CAPABILITIES_PHONE    = 1 << 5,
        SD_LLDP_SYSTEM_CAPABILITIES_DOCSIS   = 1 << 6,
        SD_LLDP_SYSTEM_CAPABILITIES_STATION  = 1 << 7,
        SD_LLDP_SYSTEM_CAPABILITIES_CVLAN    = 1 << 8,
        SD_LLDP_SYSTEM_CAPABILITIES_SVLAN    = 1 << 9,
        SD_LLDP_SYSTEM_CAPABILITIES_TPMR     = 1 << 10
};

#define SD_LLDP_SYSTEM_CAPABILITIES_ALL UINT16_MAX

#define SD_LLDP_SYSTEM_CAPABILITIES_ALL_ROUTERS                         \
        ((uint16_t)                                                     \
         (SD_LLDP_SYSTEM_CAPABILITIES_REPEATER |                        \
          SD_LLDP_SYSTEM_CAPABILITIES_BRIDGE |                          \
          SD_LLDP_SYSTEM_CAPABILITIES_WLAN_AP |                         \
          SD_LLDP_SYSTEM_CAPABILITIES_ROUTER |                          \
          SD_LLDP_SYSTEM_CAPABILITIES_DOCSIS |                          \
          SD_LLDP_SYSTEM_CAPABILITIES_CVLAN |                           \
          SD_LLDP_SYSTEM_CAPABILITIES_SVLAN |                           \
          SD_LLDP_SYSTEM_CAPABILITIES_TPMR))

#define SD_LLDP_OUI_802_1 (const uint8_t[]) { 0x00, 0x80, 0xc2 }
#define SD_LLDP_OUI_802_3 (const uint8_t[]) { 0x00, 0x12, 0x0f }

#define _SD_LLDP_OUI_IANA 0x00, 0x00, 0x5E
#define SD_LLDP_OUI_IANA  (const uint8_t[]) { _SD_LLDP_OUI_IANA }

#define SD_LLDP_OUI_IANA_SUBTYPE_MUD  0x01
#define SD_LLDP_OUI_IANA_MUD                                            \
        (const uint8_t[]) { _SD_LLDP_OUI_IANA, SD_LLDP_OUI_IANA_SUBTYPE_MUD }

/* IEEE 802.1AB-2009 Annex E */
enum {
        SD_LLDP_OUI_802_1_SUBTYPE_PORT_VLAN_ID          = 1,
        SD_LLDP_OUI_802_1_SUBTYPE_PORT_PROTOCOL_VLAN_ID = 2,
        SD_LLDP_OUI_802_1_SUBTYPE_VLAN_NAME             = 3,
        SD_LLDP_OUI_802_1_SUBTYPE_PROTOCOL_IDENTITY     = 4,
        SD_LLDP_OUI_802_1_SUBTYPE_VID_USAGE_DIGEST      = 5,
        SD_LLDP_OUI_802_1_SUBTYPE_MANAGEMENT_VID        = 6,
        SD_LLDP_OUI_802_1_SUBTYPE_LINK_AGGREGATION      = 7
};

/* IEEE 802.1AB-2009 Annex F */
enum {
        SD_LLDP_OUI_802_3_SUBTYPE_MAC_PHY_CONFIG_STATUS = 1,
        SD_LLDP_OUI_802_3_SUBTYPE_POWER_VIA_MDI         = 2,
        SD_LLDP_OUI_802_3_SUBTYPE_LINK_AGGREGATION      = 3,
        SD_LLDP_OUI_802_3_SUBTYPE_MAXIMUM_FRAME_SIZE    = 4
};

_SD_END_DECLARATIONS;

#endif
