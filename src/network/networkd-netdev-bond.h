/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

typedef struct Bond Bond;

#include "networkd-netdev.h"

typedef enum BondMode {
        NETDEV_BOND_MODE_BALANCE_RR,
        NETDEV_BOND_MODE_ACTIVE_BACKUP,
        NETDEV_BOND_MODE_BALANCE_XOR,
        NETDEV_BOND_MODE_BROADCAST,
        NETDEV_BOND_MODE_802_3AD,
        NETDEV_BOND_MODE_BALANCE_TLB,
        NETDEV_BOND_MODE_BALANCE_ALB,
        _NETDEV_BOND_MODE_MAX,
        _NETDEV_BOND_MODE_INVALID = -1
} BondMode;

typedef enum BondXmitHashPolicy {
        NETDEV_BOND_XMIT_HASH_POLICY_LAYER2,
        NETDEV_BOND_XMIT_HASH_POLICY_LAYER34,
        NETDEV_BOND_XMIT_HASH_POLICY_LAYER23,
        NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23,
        NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34,
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

typedef struct ArpIpTarget {
        union in_addr_union ip;

        LIST_FIELDS(struct ArpIpTarget, arp_ip_target);
} ArpIpTarget;

struct Bond {
        NetDev meta;

        BondMode mode;
        BondXmitHashPolicy xmit_hash_policy;
        BondLacpRate lacp_rate;
        BondAdSelect ad_select;
        BondFailOverMac fail_over_mac;
        BondArpValidate arp_validate;
        BondArpAllTargets arp_all_targets;
        BondPrimaryReselect primary_reselect;

        bool all_slaves_active;

        unsigned resend_igmp;
        unsigned packets_per_slave;
        unsigned num_grat_arp;
        unsigned min_links;

        usec_t miimon;
        usec_t updelay;
        usec_t downdelay;
        usec_t arp_interval;
        usec_t lp_interval;

        int n_arp_ip_targets;
        ArpIpTarget *arp_ip_targets;
};

extern const NetDevVTable bond_vtable;

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

int config_parse_bond_mode(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_xmit_hash_policy(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_lacp_rate(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_ad_select(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_fail_over_mac(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_arp_validate(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_arp_all_targets(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_bond_primary_reselect(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_arp_ip_target_address(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
