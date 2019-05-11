/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <netinet/in.h>
#include <linux/if_bonding.h>

#include "in-addr-util.h"
#include "netdev.h"
#include "ordered-set.h"

/*
 * Maximum number of targets supported by the kernel for a single
 * bond netdev.
 */
#define NETDEV_BOND_ARP_TARGETS_MAX 16

typedef enum BondMode {
        NETDEV_BOND_MODE_BALANCE_RR    = BOND_MODE_ROUNDROBIN,
        NETDEV_BOND_MODE_ACTIVE_BACKUP = BOND_MODE_ACTIVEBACKUP,
        NETDEV_BOND_MODE_BALANCE_XOR   = BOND_MODE_XOR,
        NETDEV_BOND_MODE_BROADCAST     = BOND_MODE_BROADCAST,
        NETDEV_BOND_MODE_802_3AD       = BOND_MODE_8023AD,
        NETDEV_BOND_MODE_BALANCE_TLB   = BOND_MODE_TLB,
        NETDEV_BOND_MODE_BALANCE_ALB   = BOND_MODE_ALB,
        _NETDEV_BOND_MODE_MAX,
        _NETDEV_BOND_MODE_INVALID      = -1
} BondMode;

typedef enum BondXmitHashPolicy {
        NETDEV_BOND_XMIT_HASH_POLICY_LAYER2   = BOND_XMIT_POLICY_LAYER2,
        NETDEV_BOND_XMIT_HASH_POLICY_LAYER34  = BOND_XMIT_POLICY_LAYER34,
        NETDEV_BOND_XMIT_HASH_POLICY_LAYER23  = BOND_XMIT_POLICY_LAYER23,
        NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23  = BOND_XMIT_POLICY_ENCAP23,
        NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34  = BOND_XMIT_POLICY_ENCAP34,
        _NETDEV_BOND_XMIT_HASH_POLICY_MAX,
        _NETDEV_BOND_XMIT_HASH_POLICY_INVALID = -1
} BondXmitHashPolicy;

typedef enum BondLacpRate {
        NETDEV_BOND_LACP_RATE_SLOW,
        NETDEV_BOND_LACP_RATE_FAST,
        _NETDEV_BOND_LACP_RATE_MAX,
        _NETDEV_BOND_LACP_RATE_INVALID = -1,
} BondLacpRate;

typedef enum BondAdSelect {
        NETDEV_BOND_AD_SELECT_STABLE,
        NETDEV_BOND_AD_SELECT_BANDWIDTH,
        NETDEV_BOND_AD_SELECT_COUNT,
        _NETDEV_BOND_AD_SELECT_MAX,
        _NETDEV_BOND_AD_SELECT_INVALID = -1,
} BondAdSelect;

typedef enum BondFailOverMac {
        NETDEV_BOND_FAIL_OVER_MAC_NONE,
        NETDEV_BOND_FAIL_OVER_MAC_ACTIVE,
        NETDEV_BOND_FAIL_OVER_MAC_FOLLOW,
        _NETDEV_BOND_FAIL_OVER_MAC_MAX,
        _NETDEV_BOND_FAIL_OVER_MAC_INVALID = -1,
} BondFailOverMac;

typedef enum BondArpValidate {
        NETDEV_BOND_ARP_VALIDATE_NONE,
        NETDEV_BOND_ARP_VALIDATE_ACTIVE,
        NETDEV_BOND_ARP_VALIDATE_BACKUP,
        NETDEV_BOND_ARP_VALIDATE_ALL,
        _NETDEV_BOND_ARP_VALIDATE_MAX,
        _NETDEV_BOND_ARP_VALIDATE_INVALID = -1,
} BondArpValidate;

typedef enum BondArpAllTargets {
        NETDEV_BOND_ARP_ALL_TARGETS_ANY,
        NETDEV_BOND_ARP_ALL_TARGETS_ALL,
        _NETDEV_BOND_ARP_ALL_TARGETS_MAX,
        _NETDEV_BOND_ARP_ALL_TARGETS_INVALID = -1,
} BondArpAllTargets;

typedef enum BondPrimaryReselect {
        NETDEV_BOND_PRIMARY_RESELECT_ALWAYS,
        NETDEV_BOND_PRIMARY_RESELECT_BETTER,
        NETDEV_BOND_PRIMARY_RESELECT_FAILURE,
        _NETDEV_BOND_PRIMARY_RESELECT_MAX,
        _NETDEV_BOND_PRIMARY_RESELECT_INVALID = -1,
} BondPrimaryReselect;

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

int link_set_bond(Link *link);

const char *bond_mode_to_string(BondMode d) _const_;
BondMode bond_mode_from_string(const char *d) _pure_;

const char *bond_xmit_hash_policy_to_string(BondXmitHashPolicy d) _const_;
BondXmitHashPolicy bond_xmit_hash_policy_from_string(const char *d) _pure_;

const char *bond_lacp_rate_to_string(BondLacpRate d) _const_;
BondLacpRate bond_lacp_rate_from_string(const char *d) _pure_;

const char *bond_fail_over_mac_to_string(BondFailOverMac d) _const_;
BondFailOverMac bond_fail_over_mac_from_string(const char *d) _pure_;

const char *bond_ad_select_to_string(BondAdSelect d) _const_;
BondAdSelect bond_ad_select_from_string(const char *d) _pure_;

const char *bond_arp_validate_to_string(BondArpValidate d) _const_;
BondArpValidate bond_arp_validate_from_string(const char *d) _pure_;

const char *bond_arp_all_targets_to_string(BondArpAllTargets d) _const_;
BondArpAllTargets bond_arp_all_targets_from_string(const char *d) _pure_;

const char *bond_primary_reselect_to_string(BondPrimaryReselect d) _const_;
BondPrimaryReselect bond_primary_reselect_from_string(const char *d) _pure_;

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
