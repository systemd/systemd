/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <linux/if_bonding.h>

#include "bond-util.h"
#include "macro.h"
#include "netdev.h"
#include "ordered-set.h"

typedef struct Bond {
        NetDev meta;

        BondMode mode;
        BondXmitHashPolicy xmit_hash_policy;
        BondLacpRate lacp_rate;
        BondAdSelect ad_select;
        BondFailOverMac fail_over_mac;
        BondArpValidate arp_validate;
        BondArpAllTargets arp_all_targets;
        BondPrimaryReselect primary_reselect;

        int tlb_dynamic_lb;

        bool all_slaves_active;

        unsigned resend_igmp;
        unsigned packets_per_slave;
        unsigned num_grat_arp;
        unsigned min_links;

        uint16_t ad_actor_sys_prio;
        uint16_t ad_user_port_key;
        struct ether_addr ad_actor_system;

        usec_t miimon;
        usec_t updelay;
        usec_t downdelay;
        usec_t arp_interval;
        usec_t lp_interval;

        OrderedSet *arp_ip_targets;
} Bond;

DEFINE_NETDEV_CAST(BOND, Bond);
extern const NetDevVTable bond_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_bond_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_xmit_hash_policy);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_lacp_rate);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_ad_select);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_fail_over_mac);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_arp_validate);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_arp_all_targets);
CONFIG_PARSER_PROTOTYPE(config_parse_bond_primary_reselect);
CONFIG_PARSER_PROTOTYPE(config_parse_arp_ip_target_address);
CONFIG_PARSER_PROTOTYPE(config_parse_ad_actor_sys_prio);
CONFIG_PARSER_PROTOTYPE(config_parse_ad_user_port_key);
CONFIG_PARSER_PROTOTYPE(config_parse_ad_actor_system);
