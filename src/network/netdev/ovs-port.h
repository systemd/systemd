/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"
#include "shared-forward.h"
#include "string-table.h"

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
        uint16_t tag;             /* 802.1Q VLAN tag, VLANID_INVALID = unset */
        OVSPortVLANMode vlan_mode;
        char *trunks;             /* comma-separated VLAN IDs, parsed by reconciler */
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
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_port_vlanid);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_lacp);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_bond_mode);

DECLARE_STRING_TABLE_LOOKUP(ovs_port_type, OVSPortType);
DECLARE_STRING_TABLE_LOOKUP(ovs_port_vlan_mode, OVSPortVLANMode);
DECLARE_STRING_TABLE_LOOKUP(ovs_lacp, OVSLACP);
DECLARE_STRING_TABLE_LOOKUP(ovs_bond_mode, OVSBondMode);
