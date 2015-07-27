/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#pragma once

#define LLDP_MULTICAST_ADDR     { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }

#define ETHERTYPE_LLDP          0x88cc

/* IEEE 802.3AB Clause 9: TLV Types */
typedef enum LLDPTypes {
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
        _LLDP_TYPE_MAX,
        _LLDP_TYPE_INVALID             = -1,
} LLDPTypes;

/* IEEE 802.3AB Clause 9.5.2: Chassis subtypes */
typedef enum LLDPChassisSubtypes {
        LLDP_CHASSIS_SUBTYPE_RESERVED            = 0,
        LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT   = 1,
        LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS     = 2,
        LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT      = 3,
        LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS         = 4,
        LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS     = 5,
        LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME      = 6,
        LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED    = 7,
        _LLDP_CHASSIS_SUBTYPE_MAX,
        _LLDP_CHASSIS_SUBTYPE_INVALID            = -1,
} LLDPChassisSubtypes;

/* IEEE 802.3AB Clause 9.5.3: Port subtype */
typedef enum LLDPPortSubtypes  {
        LLDP_PORT_SUBTYPE_RESERVED           = 0,
        LLDP_PORT_SUBTYPE_INTERFACE_ALIAS    = 1,
        LLDP_PORT_SUBTYPE_PORT_COMPONENT     = 2,
        LLDP_PORT_SUBTYPE_MAC_ADDRESS        = 3,
        LLDP_PORT_SUBTYPE_NETWORK            = 4,
        LLDP_PORT_SUBTYPE_INTERFACE_NAME     = 5,
        LLDP_PORT_SUBTYPE_AGENT_CIRCUIT_ID   = 6,
        LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED   = 7,
        _LLDP_PORT_SUBTYPE_MAX,
        _LLDP_PORT_SUBTYPE_INVALID           = -1
} LLDPPortSubtypes;

typedef enum LLDPSystemCapabilities {
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
        _LLDP_SYSTEM_CAPABILITIES_MAX,
        _LLDP_SYSTEM_CAPABILITIES_INVALID     = -1,
} LLDPSystemCapabilities;

typedef enum LLDPMedSubtype {
        LLDP_MED_SUBTYPE_RESERVED          = 0,
        LLDP_MED_SUBTYPE_CAPABILITIES      = 1,
        LLDP_MED_SUBTYPE_NETWORK_POLICY    = 2,
        LLDP_MED_SUBTYPE_LOCATION_ID       = 3,
        LLDP_MED_SUBTYPE_EXTENDED_PVMDI    = 4,
        LLDP_MED_SUBTYPE_INV_HWREV         = 5,
        LLDP_MED_SUBTYPE_INV_FWREV         = 6,
        LLDP_MED_SUBTYPE_INV_SWREV         = 7,
        LLDP_MED_SUBTYPE_INV_SERIAL        = 8,
        LLDP_MED_SUBTYPE_INV_MANUFACTURER  = 9,
        LLDP_MED_SUBTYPE_INV_MODELNAME     = 10,
        LLDP_MED_SUBTYPE_INV_ASSETID       = 11,
        _LLDP_MED_SUBTYPE_MAX,
        _LLDP_MED_SUBTYPE_INVALID          = -1,
} LLDPMedSubtype;

typedef enum LLDPMedCapability {
        LLDP_MED_CAPABILITY_CAPAPILITIES   = 1 << 0,
        LLDP_MED_CAPABILITY_NETWORK_POLICY = 1 << 1,
        LLDP_MED_CAPABILITY_LOCATION_ID    = 1 << 2,
        LLDP_MED_CAPABILITY_EXTENDED_PSE   = 1 << 3,
        LLDP_MED_CAPABILITY_EXTENDED_PD    = 1 << 4,
        LLDP_MED_CAPABILITY_INVENTORY      = 1 << 5,
        LLDP_MED_CAPABILITY_MAX,
        LLDP_MED_CAPABILITY_INVALID        = -1,
} LLDPMedCapability;

#define LLDP_OUI_802_1 (uint8_t[]) { 0x00, 0x80, 0xc2 }
#define LLDP_OUI_802_3 (uint8_t[]) { 0x00, 0x12, 0x0f }

enum {
        LLDP_OUI_SUBTYPE_802_1_PORT_VLAN_ID            = 1,
        LLDP_OUI_SUBTYPE_802_1_PORT_PROTOCOL_VLAN_ID   = 2,
        LLDP_OUI_SUBTYPE_802_1_VLAN_NAME               = 3,
        LLDP_OUI_SUBTYPE_802_1_PROTOCOL_IDENTITY       = 4,
        LLDP_OUI_SUBTYPE_802_1_VID_USAGE_DIGEST        = 5,
        LLDP_OUI_SUBTYPE_802_1_MANAGEMENT_VID          = 6,
        LLDP_OUI_SUBTYPE_802_1_LINK_AGGREGATION        = 7,
};
