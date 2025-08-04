/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if_link.h>
#include <net/ethernet.h>

#include "conf-parser-forward.h"
#include "forward.h"

typedef enum SRIOVAttribute {
        SR_IOV_VF_MAC,
        SR_IOV_VF_SPOOFCHK,
        SR_IOV_VF_RSS_QUERY_EN,
        SR_IOV_VF_TRUST,
        SR_IOV_VF_LINK_STATE,
        SR_IOV_VF_VLAN_LIST,
        _SR_IOV_ATTRIBUTE_MAX,
        _SR_IOV_ATTRIBUTE_INVALID = -EINVAL,
} SRIOVAttribute;

typedef enum SRIOVLinkState {
        SR_IOV_LINK_STATE_AUTO     = IFLA_VF_LINK_STATE_AUTO,
        SR_IOV_LINK_STATE_ENABLE   = IFLA_VF_LINK_STATE_ENABLE,
        SR_IOV_LINK_STATE_DISABLE  = IFLA_VF_LINK_STATE_DISABLE,
        _SR_IOV_LINK_STATE_MAX,
        _SR_IOV_LINK_STATE_INVALID = -EINVAL,
} SRIOVLinkState;

typedef struct SRIOV {
        ConfigSection *section;
        OrderedHashmap *sr_iov_by_section;

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

const char* sr_iov_attribute_to_string(SRIOVAttribute a) _const_;

void sr_iov_hash_func(const SRIOV *sr_iov, struct siphash *state);
int sr_iov_compare_func(const SRIOV *s1, const SRIOV *s2);
bool sr_iov_has_config(SRIOV *sr_iov, SRIOVAttribute attr);
int sr_iov_set_netlink_message(SRIOV *sr_iov, SRIOVAttribute attr, sd_netlink_message *req);
int sr_iov_get_num_vfs(sd_device *device, uint32_t *ret);
int sr_iov_set_num_vfs(sd_device *device, uint32_t num_vfs, OrderedHashmap *sr_iov_by_section);
int sr_iov_drop_invalid_sections(uint32_t num_vfs, OrderedHashmap *sr_iov_by_section);

CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_uint32);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_boolean);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_link_state);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_vlan_proto);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_mac);
CONFIG_PARSER_PROTOTYPE(config_parse_sr_iov_num_vfs);
