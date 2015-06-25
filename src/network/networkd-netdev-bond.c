/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014  Tom Gundersen <teg@jklm.no>
    Copyright 2014  Susant Sahani

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

#include <netinet/ether.h>
#include <linux/if_bonding.h>

#include "conf-parser.h"
#include "sd-netlink.h"
#include "networkd-netdev-bond.h"
#include "missing.h"

/*
 * Number of seconds between instances where the bonding
 * driver sends learning packets to each slaves peer switch
 */
#define LEARNING_PACKETS_INTERVAL_MIN_SEC       (1 * USEC_PER_SEC)
#define LEARNING_PACKETS_INTERVAL_MAX_SEC       (0x7fffffff * USEC_PER_SEC)

/* Number of IGMP membership reports to be issued after
 * a failover event.
 */
#define RESEND_IGMP_MIN           0
#define RESEND_IGMP_MAX           255
#define RESEND_IGMP_DEFAULT       1

/*
 * Number of packets to transmit through a slave before
 * moving to the next one.
 */
#define PACKETS_PER_SLAVE_MIN     0
#define PACKETS_PER_SLAVE_MAX     65535
#define PACKETS_PER_SLAVE_DEFAULT 1

/*
 * Number of peer notifications (gratuitous ARPs and
 * unsolicited IPv6 Neighbor Advertisements) to be issued after a
 * failover event.
 */
#define GRATUITOUS_ARP_MIN        0
#define GRATUITOUS_ARP_MAX        255
#define GRATUITOUS_ARP_DEFAULT    1

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
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_mode, bond_mode, BondMode, "Failed to parse bond mode");

static const char* const bond_xmit_hash_policy_table[_NETDEV_BOND_XMIT_HASH_POLICY_MAX] = {
        [NETDEV_BOND_XMIT_HASH_POLICY_LAYER2] = "layer2",
        [NETDEV_BOND_XMIT_HASH_POLICY_LAYER34] = "layer3+4",
        [NETDEV_BOND_XMIT_HASH_POLICY_LAYER23] = "layer2+3",
        [NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23] = "encap2+3",
        [NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34] = "encap3+4",
};

DEFINE_STRING_TABLE_LOOKUP(bond_xmit_hash_policy, BondXmitHashPolicy);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_xmit_hash_policy,
                         bond_xmit_hash_policy,
                         BondXmitHashPolicy,
                         "Failed to parse bond transmit hash policy")

static const char* const bond_lacp_rate_table[_NETDEV_BOND_LACP_RATE_MAX] = {
        [NETDEV_BOND_LACP_RATE_SLOW] = "slow",
        [NETDEV_BOND_LACP_RATE_FAST] = "fast",
};

DEFINE_STRING_TABLE_LOOKUP(bond_lacp_rate, BondLacpRate);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_lacp_rate, bond_lacp_rate, BondLacpRate, "Failed to parse bond lacp rate")

static const char* const bond_ad_select_table[_NETDEV_BOND_AD_SELECT_MAX] = {
        [NETDEV_BOND_AD_SELECT_STABLE] = "stable",
        [NETDEV_BOND_AD_SELECT_BANDWIDTH] = "bandwidth",
        [NETDEV_BOND_AD_SELECT_COUNT] = "count",
};

DEFINE_STRING_TABLE_LOOKUP(bond_ad_select, BondAdSelect);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_ad_select, bond_ad_select, BondAdSelect, "Failed to parse bond AD select");

static const char* const bond_fail_over_mac_table[_NETDEV_BOND_FAIL_OVER_MAC_MAX] = {
        [NETDEV_BOND_FAIL_OVER_MAC_NONE] = "none",
        [NETDEV_BOND_FAIL_OVER_MAC_ACTIVE] = "active",
        [NETDEV_BOND_FAIL_OVER_MAC_FOLLOW] = "follow",
};

DEFINE_STRING_TABLE_LOOKUP(bond_fail_over_mac, BondFailOverMac);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_fail_over_mac, bond_fail_over_mac, BondFailOverMac, "Failed to parse bond fail over MAC");

static const char *const bond_arp_validate_table[_NETDEV_BOND_ARP_VALIDATE_MAX] = {
        [NETDEV_BOND_ARP_VALIDATE_NONE] = "none",
        [NETDEV_BOND_ARP_VALIDATE_ACTIVE]= "active",
        [NETDEV_BOND_ARP_VALIDATE_BACKUP]= "backup",
        [NETDEV_BOND_ARP_VALIDATE_ALL]= "all",
};

DEFINE_STRING_TABLE_LOOKUP(bond_arp_validate, BondArpValidate);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_arp_validate, bond_arp_validate, BondArpValidate, "Failed to parse bond arp validate");

static const char *const bond_arp_all_targets_table[_NETDEV_BOND_ARP_ALL_TARGETS_MAX] = {
        [NETDEV_BOND_ARP_ALL_TARGETS_ANY] = "any",
        [NETDEV_BOND_ARP_ALL_TARGETS_ALL] = "all",
};

DEFINE_STRING_TABLE_LOOKUP(bond_arp_all_targets, BondArpAllTargets);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_arp_all_targets, bond_arp_all_targets, BondArpAllTargets, "Failed to parse bond Arp all targets");

static const char *bond_primary_reselect_table[_NETDEV_BOND_PRIMARY_RESELECT_MAX] = {
        [NETDEV_BOND_PRIMARY_RESELECT_ALWAYS] = "always",
        [NETDEV_BOND_PRIMARY_RESELECT_BETTER]= "better",
        [NETDEV_BOND_PRIMARY_RESELECT_FAILURE]= "failure",
};

DEFINE_STRING_TABLE_LOOKUP(bond_primary_reselect, BondPrimaryReselect);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_primary_reselect, bond_primary_reselect, BondPrimaryReselect, "Failed to parse bond primary reselect");

static uint8_t bond_mode_to_kernel(BondMode mode) {
        switch (mode) {
        case NETDEV_BOND_MODE_BALANCE_RR:
                return BOND_MODE_ROUNDROBIN;
        case NETDEV_BOND_MODE_ACTIVE_BACKUP:
                return BOND_MODE_ACTIVEBACKUP;
        case NETDEV_BOND_MODE_BALANCE_XOR:
                return BOND_MODE_XOR;
        case NETDEV_BOND_MODE_BROADCAST:
                return BOND_MODE_BROADCAST;
        case NETDEV_BOND_MODE_802_3AD:
                return BOND_MODE_8023AD;
        case NETDEV_BOND_MODE_BALANCE_TLB:
                return BOND_MODE_TLB;
        case NETDEV_BOND_MODE_BALANCE_ALB:
                return BOND_MODE_ALB;
        default:
                return (uint8_t) -1;
        }
}

static uint8_t bond_xmit_hash_policy_to_kernel(BondXmitHashPolicy policy) {
        switch (policy) {
        case NETDEV_BOND_XMIT_HASH_POLICY_LAYER2:
                return BOND_XMIT_POLICY_LAYER2;
        case NETDEV_BOND_XMIT_HASH_POLICY_LAYER34:
                return BOND_XMIT_POLICY_LAYER34;
        case NETDEV_BOND_XMIT_HASH_POLICY_LAYER23:
                return BOND_XMIT_POLICY_LAYER23;
        case NETDEV_BOND_XMIT_HASH_POLICY_ENCAP23:
                return BOND_XMIT_POLICY_ENCAP23;
        case NETDEV_BOND_XMIT_HASH_POLICY_ENCAP34:
                return BOND_XMIT_POLICY_ENCAP34;
        default:
                return (uint8_t) -1;
        }
}

static int netdev_bond_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Bond *b = BOND(netdev);
        ArpIpTarget *target = NULL;
        int r, i = 0;

        assert(netdev);
        assert(!link);
        assert(b);
        assert(m);

        if (b->mode != _NETDEV_BOND_MODE_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_MODE,
                                              bond_mode_to_kernel(b->mode));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_MODE attribute: %m");
        }

        if (b->xmit_hash_policy != _NETDEV_BOND_XMIT_HASH_POLICY_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_XMIT_HASH_POLICY,
                                              bond_xmit_hash_policy_to_kernel(b->xmit_hash_policy));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_XMIT_HASH_POLICY attribute: %m");
        }

        if (b->lacp_rate != _NETDEV_BOND_LACP_RATE_INVALID &&
            b->mode == NETDEV_BOND_MODE_802_3AD) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_AD_LACP_RATE, b->lacp_rate );
                if (r < 0) {
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_AD_LACP_RATE attribute: %m");
                }
        }

        if (b->miimon != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_MIIMON, b->miimon / USEC_PER_MSEC);
                if (r < 0)
                        log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_BOND_MIIMON attribute: %m");
        }

        if (b->downdelay != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_DOWNDELAY, b->downdelay / USEC_PER_MSEC);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_DOWNDELAY attribute: %m");
        }

        if (b->updelay != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_UPDELAY, b->updelay / USEC_PER_MSEC);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_UPDELAY attribute: %m");
        }

        if (b->arp_interval != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_INTERVAL, b->arp_interval / USEC_PER_MSEC);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_INTERVAL attribute: %m");

                if ((b->lp_interval >= LEARNING_PACKETS_INTERVAL_MIN_SEC) &&
                    (b->lp_interval <= LEARNING_PACKETS_INTERVAL_MAX_SEC)) {
                        r = sd_netlink_message_append_u32(m, IFLA_BOND_LP_INTERVAL, b->lp_interval / USEC_PER_SEC);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_LP_INTERVAL attribute: %m");
                }
        }

        if (b->ad_select != _NETDEV_BOND_AD_SELECT_INVALID &&
            b->mode == NETDEV_BOND_MODE_802_3AD) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_AD_SELECT, b->ad_select);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_AD_SELECT attribute: %m");
        }

        if (b->fail_over_mac != _NETDEV_BOND_FAIL_OVER_MAC_INVALID &&
            b->mode == NETDEV_BOND_MODE_ACTIVE_BACKUP) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_FAIL_OVER_MAC, b->fail_over_mac);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_FAIL_OVER_MAC attribute: %m");
        }

        if (b->arp_validate != _NETDEV_BOND_ARP_VALIDATE_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_VALIDATE, b->arp_validate);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_VALIDATE attribute: %m");
        }

        if (b->arp_all_targets != _NETDEV_BOND_ARP_ALL_TARGETS_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_ALL_TARGETS, b->arp_all_targets);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_VALIDATE attribute: %m");
        }

        if (b->primary_reselect != _NETDEV_BOND_PRIMARY_RESELECT_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_ALL_TARGETS, b->primary_reselect);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_ALL_TARGETS attribute: %m");
        }

        if (b->resend_igmp <= RESEND_IGMP_MAX) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_RESEND_IGMP, b->resend_igmp);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_RESEND_IGMP attribute: %m");
        }

        if (b->packets_per_slave <= PACKETS_PER_SLAVE_MAX &&
            b->mode == NETDEV_BOND_MODE_BALANCE_RR) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_PACKETS_PER_SLAVE, b->packets_per_slave);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_PACKETS_PER_SLAVE attribute: %m");
        }

        if (b->num_grat_arp <= GRATUITOUS_ARP_MAX) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_NUM_PEER_NOTIF, b->num_grat_arp);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_NUM_PEER_NOTIF attribute: %m");
        }

        if (b->min_links != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_MIN_LINKS, b->min_links);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_MIN_LINKS attribute: %m");
        }

        r = sd_netlink_message_append_u8(m, IFLA_BOND_ALL_SLAVES_ACTIVE, b->all_slaves_active);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ALL_SLAVES_ACTIVE attribute: %m");

        if (b->arp_interval > 0)  {
                if (b->n_arp_ip_targets > 0) {

                        r = sd_netlink_message_open_container(m, IFLA_BOND_ARP_IP_TARGET);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not open contaniner IFLA_BOND_ARP_IP_TARGET : %m");

                        LIST_FOREACH(arp_ip_target, target, b->arp_ip_targets) {
                                r = sd_netlink_message_append_u32(m, i++, target->ip.in.s_addr);
                                if (r < 0)
                                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_ALL_TARGETS attribute: %m");
                        }

                        r = sd_netlink_message_close_container(m);
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not close contaniner IFLA_BOND_ARP_IP_TARGET : %m");
                }
        }

        return 0;
}

int config_parse_arp_ip_target_address(const char *unit,
                                       const char *filename,
                                       unsigned line,
                                       const char *section,
                                       unsigned section_line,
                                       const char *lvalue,
                                       int ltype,
                                       const char *rvalue,
                                       void *data,
                                       void *userdata) {
        Bond *b = userdata;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                _cleanup_free_ ArpIpTarget *buffer = NULL;
                _cleanup_free_ char *n = NULL;
                int f;

                n = strndup(word, l);
                if (!n)
                        return -ENOMEM;

                buffer = new0(ArpIpTarget, 1);
                if (!buffer)
                        return -ENOMEM;

                r = in_addr_from_string_auto(n, &f, &buffer->ip);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Bond ARP ip target address is invalid, ignoring assignment: %s", n);
                        return 0;
                }

                if (f != AF_INET) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Bond ARP ip target address is invalid, ignoring assignment: %s", n);
                        return 0;
                }

                LIST_PREPEND(arp_ip_target, b->arp_ip_targets, buffer);
                b->n_arp_ip_targets ++;

                buffer = NULL;
        }

        if (b->n_arp_ip_targets > NETDEV_BOND_ARP_TARGETS_MAX)
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL, "More than the maximum number of kernel-supported ARP ip targets specified: %d > %d", b->n_arp_ip_targets, NETDEV_BOND_ARP_TARGETS_MAX);

        return 0;
}

static void bond_done(NetDev *netdev) {
        ArpIpTarget *t = NULL, *n = NULL;
        Bond *b = BOND(netdev);

        assert(netdev);
        assert(b);

        LIST_FOREACH_SAFE(arp_ip_target, t, n, b->arp_ip_targets)
                free(t);

        b->arp_ip_targets = NULL;
}

static void bond_init(NetDev *netdev) {
        Bond *b = BOND(netdev);

        assert(netdev);
        assert(b);

        b->mode = _NETDEV_BOND_MODE_INVALID;
        b->xmit_hash_policy = _NETDEV_BOND_XMIT_HASH_POLICY_INVALID;
        b->lacp_rate = _NETDEV_BOND_LACP_RATE_INVALID;
        b->ad_select = _NETDEV_BOND_AD_SELECT_INVALID;
        b->fail_over_mac = _NETDEV_BOND_FAIL_OVER_MAC_INVALID;
        b->arp_validate = _NETDEV_BOND_ARP_VALIDATE_INVALID;
        b->arp_all_targets = _NETDEV_BOND_ARP_ALL_TARGETS_INVALID;
        b->primary_reselect = _NETDEV_BOND_PRIMARY_RESELECT_INVALID;

        b->all_slaves_active = false;

        b->resend_igmp = RESEND_IGMP_DEFAULT;
        b->packets_per_slave = PACKETS_PER_SLAVE_DEFAULT;
        b->num_grat_arp = GRATUITOUS_ARP_DEFAULT;
        b->lp_interval = LEARNING_PACKETS_INTERVAL_MIN_SEC;

        LIST_HEAD_INIT(b->arp_ip_targets);
        b->n_arp_ip_targets = 0;
}

const NetDevVTable bond_vtable = {
        .object_size = sizeof(Bond),
        .init = bond_init,
        .done = bond_done,
        .sections = "Match\0NetDev\0Bond\0",
        .fill_message_create = netdev_bond_fill_message_create,
        .create_type = NETDEV_CREATE_MASTER,
};
