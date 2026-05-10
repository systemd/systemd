/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "netdev.h"
#include "networkd-forward.h"

typedef struct OVSBridge {
        NetDev meta;

        char *fail_mode;          /* "standalone" or "secure" */
        int stp;                  /* tristate */
        int rstp;                 /* tristate */
        int mcast_snooping;       /* tristate */
        char *datapath_type;      /* "system" or "netdev" */
        char **protocols;         /* OpenFlow versions */
        char *datapath_id;        /* 16 hex chars */
} OVSBridge;

DEFINE_NETDEV_CAST(OVS_BRIDGE, OVSBridge);
extern const NetDevVTable ovs_bridge_vtable;
CONFIG_PARSER_PROTOTYPE(config_parse_ovs_bridge_fail_mode);
