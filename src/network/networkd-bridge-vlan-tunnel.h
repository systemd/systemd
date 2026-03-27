/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

typedef struct BridgeVLANTunnel {
        Network *network;
        ConfigSection *section;

        uint16_t vlan_id;
        uint16_t vlan_id_end;
        uint32_t tunnel_id;
        uint32_t tunnel_id_end;
} BridgeVLANTunnel;

void network_drop_invalid_bridge_vlan_tunnel_entries(Network *network);

int bridge_vlan_tunnel_append_info(Link *link, sd_netlink_message *m);
bool link_has_bridge_vlan_tunnel(Link *link);

CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_tunnel_vlan);
CONFIG_PARSER_PROTOTYPE(config_parse_bridge_vlan_tunnel_id);
