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
#include <arpa/inet.h>
#include <linux/if_bonding.h>

#include "conf-parser.h"
#include "sd-rtnl.h"
#include "networkd-netdev-bond.h"
#include "missing.h"

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

static int netdev_bond_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        Bond *b = BOND(netdev);
        int r;

        assert(netdev);
        assert(!link);
        assert(b);
        assert(m);

        if (b->mode != _NETDEV_BOND_MODE_INVALID) {
                r = sd_rtnl_message_append_u8(m, IFLA_BOND_MODE,
                                              bond_mode_to_kernel(b->mode));
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_MODE attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (b->xmit_hash_policy != _NETDEV_BOND_XMIT_HASH_POLICY_INVALID) {
                r = sd_rtnl_message_append_u8(m, IFLA_BOND_XMIT_HASH_POLICY,
                                              bond_xmit_hash_policy_to_kernel(b->xmit_hash_policy));
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_XMIT_HASH_POLICY attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (b->lacp_rate != _NETDEV_BOND_LACP_RATE_INVALID &&
            b->mode == NETDEV_BOND_MODE_802_3AD) {
                r = sd_rtnl_message_append_u8(m, IFLA_BOND_AD_LACP_RATE, b->lacp_rate );
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_AD_LACP_RATE attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (b->miimon != 0) {
                r = sd_rtnl_message_append_u32(m, IFLA_BOND_MIIMON, b->miimon / USEC_PER_MSEC);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_BOND_MIIMON attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (b->downdelay != 0) {
                r = sd_rtnl_message_append_u32(m, IFLA_BOND_DOWNDELAY, b->downdelay / USEC_PER_MSEC);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_DOWNDELAY attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (b->updelay != 0) {
                r = sd_rtnl_message_append_u32(m, IFLA_BOND_UPDELAY, b->updelay / USEC_PER_MSEC);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_UPDELAY attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        return 0;
}

static void bond_init(NetDev *netdev) {
        Bond *b = BOND(netdev);

        assert(netdev);
        assert(b);

        b->mode = _NETDEV_BOND_MODE_INVALID;
        b->xmit_hash_policy = _NETDEV_BOND_XMIT_HASH_POLICY_INVALID;
        b->lacp_rate = _NETDEV_BOND_LACP_RATE_INVALID;
}

const NetDevVTable bond_vtable = {
        .object_size = sizeof(Bond),
        .init = bond_init,
        .sections = "Match\0NetDev\0Bond\0",
        .fill_message_create = netdev_bond_fill_message_create,
        .create_type = NETDEV_CREATE_MASTER,
};
