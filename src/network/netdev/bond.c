/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if_arp.h>

#include "alloc-util.h"
#include "bond.h"
#include "bond-util.h"
#include "conf-parser.h"
#include "ether-addr-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "string-table.h"

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

DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_mode, bond_mode, BondMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_xmit_hash_policy,
                         bond_xmit_hash_policy,
                         BondXmitHashPolicy);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_lacp_rate, bond_lacp_rate, BondLacpRate);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_ad_select, bond_ad_select, BondAdSelect);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_fail_over_mac, bond_fail_over_mac, BondFailOverMac);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_arp_validate, bond_arp_validate, BondArpValidate);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_arp_all_targets, bond_arp_all_targets, BondArpAllTargets);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_primary_reselect, bond_primary_reselect, BondPrimaryReselect);

static int netdev_bond_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Bond *b = BOND(netdev);
        int r;

        assert(netdev->manager);
        assert(!link);
        assert(m);

        if (netdev->ifindex > 0) {
                r = link_get_by_index(netdev->manager, netdev->ifindex, &link);
                if (r < 0)
                        return r;
        }

        bool up = link && FLAGS_SET(link->flags, IFF_UP);
        bool has_slaves = link && !set_isempty(link->slaves);

        if (b->mode != _NETDEV_BOND_MODE_INVALID && !up && !has_slaves) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_MODE, b->mode);
                if (r < 0)
                        return r;
        }

        if (b->xmit_hash_policy != _NETDEV_BOND_XMIT_HASH_POLICY_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_XMIT_HASH_POLICY, b->xmit_hash_policy);
                if (r < 0)
                        return r;
        }

        if (b->lacp_rate != _NETDEV_BOND_LACP_RATE_INVALID &&
            b->mode == NETDEV_BOND_MODE_802_3AD &&
            !up) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_AD_LACP_RATE, b->lacp_rate);
                if (r < 0)
                        return r;
        }

        if (b->miimon != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_MIIMON, b->miimon / USEC_PER_MSEC);
                if (r < 0)
                        return r;
        }

        if (b->peer_notify_delay != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_PEER_NOTIF_DELAY, b->peer_notify_delay / USEC_PER_MSEC);
                if (r < 0)
                        return r;
        }

        if (b->downdelay != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_DOWNDELAY, b->downdelay / USEC_PER_MSEC);
                if (r < 0)
                        return r;
        }

        if (b->updelay != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_UPDELAY, b->updelay / USEC_PER_MSEC);
                if (r < 0)
                        return r;
        }

        if (b->arp_interval != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_INTERVAL, b->arp_interval / USEC_PER_MSEC);
                if (r < 0)
                        return r;

                if (b->lp_interval >= LEARNING_PACKETS_INTERVAL_MIN_SEC &&
                    b->lp_interval <= LEARNING_PACKETS_INTERVAL_MAX_SEC) {
                        r = sd_netlink_message_append_u32(m, IFLA_BOND_LP_INTERVAL, b->lp_interval / USEC_PER_SEC);
                        if (r < 0)
                                return r;
                }
        }

        if (b->ad_select != _NETDEV_BOND_AD_SELECT_INVALID &&
            b->mode == NETDEV_BOND_MODE_802_3AD &&
            !up) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_AD_SELECT, b->ad_select);
                if (r < 0)
                        return r;
        }

        if (b->fail_over_mac != _NETDEV_BOND_FAIL_OVER_MAC_INVALID &&
            b->mode == NETDEV_BOND_MODE_ACTIVE_BACKUP &&
            !has_slaves) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_FAIL_OVER_MAC, b->fail_over_mac);
                if (r < 0)
                        return r;
        }

        if (b->arp_validate != _NETDEV_BOND_ARP_VALIDATE_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_VALIDATE, b->arp_validate);
                if (r < 0)
                        return r;
        }

        if (b->arp_all_targets != _NETDEV_BOND_ARP_ALL_TARGETS_INVALID) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_ARP_ALL_TARGETS, b->arp_all_targets);
                if (r < 0)
                        return r;
        }

        if (b->primary_reselect != _NETDEV_BOND_PRIMARY_RESELECT_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_PRIMARY_RESELECT, b->primary_reselect);
                if (r < 0)
                        return r;
        }

        if (b->resend_igmp <= RESEND_IGMP_MAX) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_RESEND_IGMP, b->resend_igmp);
                if (r < 0)
                        return r;
        }

        if (b->packets_per_slave <= PACKETS_PER_SLAVE_MAX &&
            b->mode == NETDEV_BOND_MODE_BALANCE_RR) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_PACKETS_PER_SLAVE, b->packets_per_slave);
                if (r < 0)
                        return r;
        }

        if (b->num_grat_arp <= GRATUITOUS_ARP_MAX) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_NUM_PEER_NOTIF, b->num_grat_arp);
                if (r < 0)
                        return r;
        }

        if (b->min_links != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_BOND_MIN_LINKS, b->min_links);
                if (r < 0)
                        return r;
        }

        if (b->ad_actor_sys_prio != 0) {
                r = sd_netlink_message_append_u16(m, IFLA_BOND_AD_ACTOR_SYS_PRIO, b->ad_actor_sys_prio);
                if (r < 0)
                        return r;
        }

        if (b->ad_user_port_key != 0 && !up) {
                r = sd_netlink_message_append_u16(m, IFLA_BOND_AD_USER_PORT_KEY, b->ad_user_port_key);
                if (r < 0)
                        return r;
        }

        if (!ether_addr_is_null(&b->ad_actor_system)) {
                r = sd_netlink_message_append_ether_addr(m, IFLA_BOND_AD_ACTOR_SYSTEM, &b->ad_actor_system);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, IFLA_BOND_ALL_SLAVES_ACTIVE, b->all_slaves_active);
        if (r < 0)
                return r;

        if (b->tlb_dynamic_lb >= 0 && !up) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_TLB_DYNAMIC_LB, b->tlb_dynamic_lb);
                if (r < 0)
                        return r;
        }

        if (b->arp_missed_max > 0) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_MISSED_MAX, b->arp_missed_max);
                if (r < 0)
                        return r;
        }

        if (b->arp_interval > 0 && !ordered_set_isempty(b->arp_ip_targets)) {
                void *val;
                int n = 0;

                r = sd_netlink_message_open_container(m, IFLA_BOND_ARP_IP_TARGET);
                if (r < 0)
                        return r;

                ORDERED_SET_FOREACH(val, b->arp_ip_targets) {
                        r = sd_netlink_message_append_u32(m, n++, PTR_TO_UINT32(val));
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_arp_ip_target_address(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        Bond *b = BOND(userdata);
        int r;

        if (isempty(rvalue)) {
                b->arp_ip_targets = ordered_set_free(b->arp_ip_targets);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *n = NULL;
                union in_addr_union ip;

                r = extract_first_word(&p, &n, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse Bond ARP IP target address, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET, n, &ip);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Bond ARP IP target address is invalid, ignoring assignment: %s", n);
                        continue;
                }

                if (ordered_set_size(b->arp_ip_targets) >= NETDEV_BOND_ARP_TARGETS_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many ARP IP targets are specified. The maximum number is %d. Ignoring assignment: %s",
                                   NETDEV_BOND_ARP_TARGETS_MAX, n);
                        continue;
                }

                r = ordered_set_ensure_put(&b->arp_ip_targets, NULL, UINT32_TO_PTR(ip.in.s_addr));
                if (r == -ENOMEM)
                        return log_oom();
                if (r == -EEXIST)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Bond ARP IP target address is duplicated, ignoring assignment: %s", n);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to store bond ARP IP target address '%s', ignoring assignment: %m", n);
        }
}

int config_parse_ad_actor_sys_prio(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        Bond *b = ASSERT_PTR(userdata);

        return config_parse_uint16_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        1, UINT16_MAX, true,
                        &b->ad_actor_sys_prio);
}

int config_parse_ad_user_port_key(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        Bond *b = ASSERT_PTR(userdata);

        return config_parse_uint16_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, 1023, /* ignoring= */ true,
                        &b->ad_user_port_key);
}

int config_parse_ad_actor_system(
                const char *unit,
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
        struct ether_addr n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_ether_addr(rvalue, &n);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Not a valid MAC address %s. Ignoring assignment: %m",
                           rvalue);
                return 0;
        }
        if (ether_addr_is_null(&n) || (n.ether_addr_octet[0] & 0x01)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Not an appropriate MAC address %s, cannot be null or multicast. Ignoring assignment.",
                           rvalue);
                return 0;
        }

        b->ad_actor_system = n;

        return 0;
}

static void bond_done(NetDev *netdev) {
        Bond *b = BOND(netdev);

        ordered_set_free(b->arp_ip_targets);
}

static void bond_init(NetDev *netdev) {
        Bond *b = BOND(netdev);

        b->mode = _NETDEV_BOND_MODE_INVALID;
        b->xmit_hash_policy = _NETDEV_BOND_XMIT_HASH_POLICY_INVALID;
        b->lacp_rate = _NETDEV_BOND_LACP_RATE_INVALID;
        b->ad_select = _NETDEV_BOND_AD_SELECT_INVALID;
        b->fail_over_mac = _NETDEV_BOND_FAIL_OVER_MAC_INVALID;
        b->arp_validate = _NETDEV_BOND_ARP_VALIDATE_INVALID;
        b->arp_all_targets = _NETDEV_BOND_ARP_ALL_TARGETS_INVALID;
        b->primary_reselect = _NETDEV_BOND_PRIMARY_RESELECT_INVALID;

        b->all_slaves_active = false;
        b->tlb_dynamic_lb = -1;

        b->resend_igmp = RESEND_IGMP_DEFAULT;
        b->packets_per_slave = PACKETS_PER_SLAVE_DEFAULT;
        b->num_grat_arp = GRATUITOUS_ARP_DEFAULT;
        b->lp_interval = LEARNING_PACKETS_INTERVAL_MIN_SEC;
}

const NetDevVTable bond_vtable = {
        .object_size = sizeof(Bond),
        .init = bond_init,
        .done = bond_done,
        .sections = NETDEV_COMMON_SECTIONS "Bond\0",
        .fill_message_create = netdev_bond_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
