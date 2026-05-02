/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"
#include "networkd-bridge-vlan.h"
#include "shared-forward.h"

typedef enum OVSPortType {
        OVS_PORT_TYPE_INTERNAL,
        OVS_PORT_TYPE_PATCH,
        OVS_PORT_TYPE_BOND,
        _OVS_PORT_TYPE_MAX,
        _OVS_PORT_TYPE_INVALID = -EINVAL,
} OVSPortType;

typedef enum OVSPortVLANMode {
        OVS_PORT_VLAN_MODE_TRUNK,
        OVS_PORT_VLAN_MODE_ACCESS,
        OVS_PORT_VLAN_MODE_NATIVE_TAGGED,
        OVS_PORT_VLAN_MODE_NATIVE_UNTAGGED,
        OVS_PORT_VLAN_MODE_DOT1Q_TUNNEL,
        _OVS_PORT_VLAN_MODE_MAX,
        _OVS_PORT_VLAN_MODE_INVALID = -EINVAL,
} OVSPortVLANMode;

typedef enum OVSLACP {
        OVS_LACP_OFF,
        OVS_LACP_ACTIVE,
        OVS_LACP_PASSIVE,
        _OVS_LACP_MAX,
        _OVS_LACP_INVALID = -EINVAL,
} OVSLACP;

typedef enum OVSBondMode {
        OVS_BOND_MODE_ACTIVE_BACKUP,
        OVS_BOND_MODE_BALANCE_SLB,
        OVS_BOND_MODE_BALANCE_TCP,
        _OVS_BOND_MODE_MAX,
        _OVS_BOND_MODE_INVALID = -EINVAL,
} OVSBondMode;

typedef struct OVSPort {
        NetDev meta;

        char *bridge;
        OVSPortType type;
        uint16_t tag;             /* 802.1Q VLAN tag (Tag= / PVID=); VLANID_INVALID = unset */
        OVSPortVLANMode vlan_mode;
        /* VLAN bitmap consumed by the reconciler. Settable via OVSPort.VLAN= range
         * syntax (BridgeVLAN-style, repeatable) or the legacy comma-separated
         * OVSPort.Trunks= (deprecated alias). */
        uint32_t vlan_bitmap[BRIDGE_VLAN_BITMAP_LEN];
        char *peer_port;          /* patch only */
        OVSLACP lacp;             /* bond only */
        OVSBondMode bond_mode;    /* bond only */
        usec_t bond_updelay;
        usec_t bond_downdelay;
} OVSPort;

DEFINE_NETDEV_CAST(OVS_PORT, OVSPort);
extern const NetDevVTable ovs_port_vtable;
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_port_type);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_port_vlan_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_lacp);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_bond_mode);

const char* ovs_port_type_to_string(OVSPortType i);
OVSPortType ovs_port_type_from_string(const char *s);

const char* ovs_port_vlan_mode_to_string(OVSPortVLANMode i);
OVSPortVLANMode ovs_port_vlan_mode_from_string(const char *s);

const char* ovs_lacp_to_string(OVSLACP i);
OVSLACP ovs_lacp_from_string(const char *s);

const char* ovs_bond_mode_to_string(OVSBondMode i);
OVSBondMode ovs_bond_mode_from_string(const char *s);
