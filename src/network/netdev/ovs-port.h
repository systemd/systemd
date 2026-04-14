/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"
#include "networkd-forward.h"
#include "time-util.h"
#include "vlan-util.h"

typedef enum OVSPortType {
        OVS_PORT_TYPE_INTERNAL,
        OVS_PORT_TYPE_PATCH,
        OVS_PORT_TYPE_BOND,
        _OVS_PORT_TYPE_MAX,
        _OVS_PORT_TYPE_INVALID = -EINVAL,
} OVSPortType;

typedef struct OVSPort {
        NetDev meta;

        char *bridge;
        OVSPortType type;
        uint16_t tag;             /* 802.1Q VLAN tag, VLANID_INVALID = unset */
        char *vlan_mode;
        char *trunks;             /* comma-separated VLAN IDs, parsed by reconciler */
        char *peer_port;          /* patch only */
        char *lacp;               /* bond: off|active|passive */
        char *bond_mode;          /* active-backup|balance-slb|balance-tcp */
        usec_t bond_updelay;
        usec_t bond_downdelay;
} OVSPort;

DEFINE_NETDEV_CAST(OVS_PORT, OVSPort);
extern const NetDevVTable ovs_port_vtable;
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_port_type);

const char* ovs_port_type_to_string(OVSPortType t);
OVSPortType ovs_port_type_from_string(const char *s);
