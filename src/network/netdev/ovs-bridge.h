/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"
#include "networkd-forward.h"

typedef enum OVSBridgeFailMode {
        OVS_BRIDGE_FAIL_MODE_STANDALONE,
        OVS_BRIDGE_FAIL_MODE_SECURE,
        _OVS_BRIDGE_FAIL_MODE_MAX,
        _OVS_BRIDGE_FAIL_MODE_INVALID = -EINVAL,
} OVSBridgeFailMode;

typedef enum OVSProtocol {
        OVS_PROTOCOL_OPENFLOW10,
        OVS_PROTOCOL_OPENFLOW11,
        OVS_PROTOCOL_OPENFLOW12,
        OVS_PROTOCOL_OPENFLOW13,
        OVS_PROTOCOL_OPENFLOW14,
        OVS_PROTOCOL_OPENFLOW15,
        _OVS_PROTOCOL_MAX,
        _OVS_PROTOCOL_INVALID = -EINVAL,
} OVSProtocol;

typedef struct OVSBridge {
        NetDev meta;

        OVSBridgeFailMode fail_mode;    /* _OVS_BRIDGE_FAIL_MODE_INVALID = unset */
        int stp;                  /* tristate */
        int rstp;                 /* tristate */
        int mcast_snooping;       /* tristate */
        char *datapath_type;      /* "system" or "netdev" */
        OVSProtocol *protocols;   /* _OVS_PROTOCOL_INVALID-terminated array; NULL = unset */
        char *datapath_id;        /* 16 hex chars */
} OVSBridge;

DEFINE_NETDEV_CAST(OVS_BRIDGE, OVSBridge);
extern const NetDevVTable ovs_bridge_vtable;
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_bridge_fail_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_protocols);

DECLARE_STRING_TABLE_LOOKUP(ovs_bridge_fail_mode, OVSBridgeFailMode);
DECLARE_STRING_TABLE_LOOKUP(ovs_protocol, OVSProtocol);
