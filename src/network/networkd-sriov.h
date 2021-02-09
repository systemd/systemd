/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */
#pragma once

#include <linux/if_link.h>

#include "conf-parser.h"
#include "ether-addr-util.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

typedef enum SRIOVLinkState {
        SR_IOV_LINK_STATE_AUTO = IFLA_VF_LINK_STATE_AUTO,
        SR_IOV_LINK_STATE_ENABLE = IFLA_VF_LINK_STATE_ENABLE,
        SR_IOV_LINK_STATE_DISABLE = IFLA_VF_LINK_STATE_DISABLE,
        _SR_IOV_LINK_STATE_MAX,
        _SR_IOV_LINK_STATE_INVALID = -EINVAL,
} SRIOVLinkState;

typedef struct SRIOV {
        NetworkConfigSection *section;
        Network *network;

        uint32_t vf;   /* 0 - 2147483646 */
        uint32_t vlan; /* 0 - 4095, 0 disables VLAN filter */
        uint32_t qos;
        uint16_t vlan_proto; /* ETH_P_8021Q or ETH_P_8021AD */
        int vf_spoof_check_setting;
        int query_rss;
        int trust;
        SRIOVLinkState link_state;
        struct ether_addr mac;
} SRIOV;

SRIOV *sr_iov_free(SRIOV *sr_iov);
int link_configure_sr_iov(Link *link);
void network_drop_invalid_sr_iov(Network *network);

DEFINE_NETWORK_SECTION_FUNCTIONS(SRIOV, sr_iov_free);

CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_uint32);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_link_state);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_vlan_proto);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_mac);
