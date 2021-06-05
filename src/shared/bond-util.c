/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bond-util.h"
#include "string-table.h"

static const char* const bond_mode_table[_NETDEV_BOND_MODE_MAX] = {
        [NETDEV_BOND_MODE_BALANCE_RR] = "balance-rr",
        [NETDEV_BOND_MODE_ACTIVE_BACKUP] = "active-backup",
        [NETDEV_BOND_MODE_BALANCE_XOR] = "balance-xor",
        [NETDEV_BOND_MODE_BROADCAST] = "broadcast",
        [NETDEV_BOND_MODE_802_3AD] = "802.3ad",
        [NETDEV_BOND_MODE_BALANCE_TLB] = "balance-tlb",
        [NETDEV_BOND_MODE_BALANCE_ALB] = "balance-alb",
};

DEFINE_STRING_TABLE_LOOKUP(bond_mode, BondMode);

static const char* const bond_xmit_hash_policy_table[_NETDEV_BOND_XMIT_HASH_POLICY_MAX] = {
        [NETDEV_BOND_XMIT_HASH_POLICY_LAYER2] = "layer2",
        [NETDEV_BOND_XMIT_HASH_POLICY_LAYER34] = "layer3+4",
        [NETDEV_BOND_XMIT_HASH_POLICY_LAYER23] = "layer2+3",
        [NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23] = "encap2+3",
        [NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34] = "encap3+4",
};

DEFINE_STRING_TABLE_LOOKUP(bond_xmit_hash_policy, BondXmitHashPolicy);

static const char* const bond_lacp_rate_table[_NETDEV_BOND_LACP_RATE_MAX] = {
        [NETDEV_BOND_LACP_RATE_SLOW] = "slow",
        [NETDEV_BOND_LACP_RATE_FAST] = "fast",
};

DEFINE_STRING_TABLE_LOOKUP(bond_lacp_rate, BondLacpRate);

static const char* const bond_ad_select_table[_NETDEV_BOND_AD_SELECT_MAX] = {
        [NETDEV_BOND_AD_SELECT_STABLE] = "stable",
        [NETDEV_BOND_AD_SELECT_BANDWIDTH] = "bandwidth",
        [NETDEV_BOND_AD_SELECT_COUNT] = "count",
};

DEFINE_STRING_TABLE_LOOKUP(bond_ad_select, BondAdSelect);

static const char* const bond_fail_over_mac_table[_NETDEV_BOND_FAIL_OVER_MAC_MAX] = {
        [NETDEV_BOND_FAIL_OVER_MAC_NONE] = "none",
        [NETDEV_BOND_FAIL_OVER_MAC_ACTIVE] = "active",
        [NETDEV_BOND_FAIL_OVER_MAC_FOLLOW] = "follow",
};

DEFINE_STRING_TABLE_LOOKUP(bond_fail_over_mac, BondFailOverMac);

static const char *const bond_arp_validate_table[_NETDEV_BOND_ARP_VALIDATE_MAX] = {
        [NETDEV_BOND_ARP_VALIDATE_NONE] = "none",
        [NETDEV_BOND_ARP_VALIDATE_ACTIVE]= "active",
        [NETDEV_BOND_ARP_VALIDATE_BACKUP]= "backup",
        [NETDEV_BOND_ARP_VALIDATE_ALL]= "all",
};

DEFINE_STRING_TABLE_LOOKUP(bond_arp_validate, BondArpValidate);

static const char *const bond_arp_all_targets_table[_NETDEV_BOND_ARP_ALL_TARGETS_MAX] = {
        [NETDEV_BOND_ARP_ALL_TARGETS_ANY] = "any",
        [NETDEV_BOND_ARP_ALL_TARGETS_ALL] = "all",
};

DEFINE_STRING_TABLE_LOOKUP(bond_arp_all_targets, BondArpAllTargets);

static const char *const bond_primary_reselect_table[_NETDEV_BOND_PRIMARY_RESELECT_MAX] = {
        [NETDEV_BOND_PRIMARY_RESELECT_ALWAYS] = "always",
        [NETDEV_BOND_PRIMARY_RESELECT_BETTER]= "better",
        [NETDEV_BOND_PRIMARY_RESELECT_FAILURE]= "failure",
};

DEFINE_STRING_TABLE_LOOKUP(bond_primary_reselect, BondPrimaryReselect);
