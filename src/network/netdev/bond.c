/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "bond.h"
#include "conf-parser.h"
#include "ether-addr-util.h"
#include "extract-word.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "string-table.h"
#include "string-util.h"

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

static const char *const bond_primary_reselect_table[_NETDEV_BOND_PRIMARY_RESELECT_MAX] = {
        [NETDEV_BOND_PRIMARY_RESELECT_ALWAYS] = "always",
        [NETDEV_BOND_PRIMARY_RESELECT_BETTER]= "better",
        [NETDEV_BOND_PRIMARY_RESELECT_FAILURE]= "failure",
};

DEFINE_STRING_TABLE_LOOKUP(bond_primary_reselect, BondPrimaryReselect);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_primary_reselect, bond_primary_reselect, BondPrimaryReselect, "Failed to parse bond primary reselect");

static int netdev_bond_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Bond *b;
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        b = BOND(netdev);

        assert(b);

        if (b->mode != _NETDEV_BOND_MODE_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_MODE, b->mode);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_MODE attribute: %m");
        }

        if (b->xmit_hash_policy != _NETDEV_BOND_XMIT_HASH_POLICY_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_XMIT_HASH_POLICY, b->xmit_hash_policy);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_XMIT_HASH_POLICY attribute: %m");
        }

        if (b->lacp_rate != _NETDEV_BOND_LACP_RATE_INVALID &&
            b->mode == NETDEV_BOND_MODE_802_3AD) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_AD_LACP_RATE, b->lacp_rate);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_AD_LACP_RATE attribute: %m");
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

                if (b->lp_interval >= LEARNING_PACKETS_INTERVAL_MIN_SEC &&
                    b->lp_interval <= LEARNING_PACKETS_INTERVAL_MAX_SEC) {
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
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_ALL_TARGETS attribute: %m");
        }

        if (b->primary_reselect != _NETDEV_BOND_PRIMARY_RESELECT_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_PRIMARY_RESELECT, b->primary_reselect);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_PRIMARY_RESELECT attribute: %m");
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

        if (b->ad_actor_sys_prio != 0) {
                r = sd_netlink_message_append_u16(m, IFLA_BOND_AD_ACTOR_SYS_PRIO, b->ad_actor_sys_prio);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_AD_ACTOR_SYS_PRIO attribute: %m");
        }

        if (b->ad_user_port_key != 0) {
                r = sd_netlink_message_append_u16(m, IFLA_BOND_AD_USER_PORT_KEY, b->ad_user_port_key);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_AD_USER_PORT_KEY attribute: %m");
        }

        if (!ether_addr_is_null(&b->ad_actor_system)) {
                r = sd_netlink_message_append_ether_addr(m, IFLA_BOND_AD_ACTOR_SYSTEM, &b->ad_actor_system);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_AD_ACTOR_SYSTEM attribute: %m");
        }

        r = sd_netlink_message_append_u8(m, IFLA_BOND_ALL_SLAVES_ACTIVE, b->all_slaves_active);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ALL_SLAVES_ACTIVE attribute: %m");

        if (b->tlb_dynamic_lb >= 0) {
                r = sd_netlink_message_append_u8(m, IFLA_BOND_TLB_DYNAMIC_LB, b->tlb_dynamic_lb);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_TLB_DYNAMIC_LB attribute: %m");
        }

        if (b->arp_interval > 0 && !ordered_set_isempty(b->arp_ip_targets)) {
                Iterator i;
                void *val;
                int n = 0;

                r = sd_netlink_message_open_container(m, IFLA_BOND_ARP_IP_TARGET);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not open contaniner IFLA_BOND_ARP_IP_TARGET : %m");

                ORDERED_SET_FOREACH(val, b->arp_ip_targets, i) {
                        r = sd_netlink_message_append_u32(m, n++, PTR_TO_UINT32(val));
                        if (r < 0)
                                return log_netdev_error_errno(netdev, r, "Could not append IFLA_BOND_ARP_ALL_TARGETS attribute: %m");
                }

                r = sd_netlink_message_close_container(m);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not close contaniner IFLA_BOND_ARP_IP_TARGET : %m");
        }

        return 0;
}

static int link_set_bond_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_warning_errno(link, r, "Could not set bonding interface: %m");
                return 1;
        }

        return 1;
}

int link_set_bond(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->network);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_NEWLINK, link->network->bond->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_set_flags(req, NLM_F_REQUEST | NLM_F_ACK);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set netlink flags: %m");

        r = sd_netlink_message_open_container(req, IFLA_LINKINFO);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_PROTINFO attribute: %m");

        r = sd_netlink_message_open_container_union(req, IFLA_INFO_DATA, "bond");
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_INFO_DATA attribute: %m");

        if (link->network->active_slave) {
                r = sd_netlink_message_append_u32(req, IFLA_BOND_ACTIVE_SLAVE, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_BOND_ACTIVE_SLAVE attribute: %m");
        }

        if (link->network->primary_slave) {
                r = sd_netlink_message_append_u32(req, IFLA_BOND_PRIMARY, link->ifindex);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_BOND_PRIMARY attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFLA_INFO_DATA attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, link_set_bond_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r,  "Could not send rtnetlink message: %m");

        link_ref(link);

        return r;
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

        Bond *b = userdata;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                b->arp_ip_targets = ordered_set_free(b->arp_ip_targets);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *n = NULL;
                union in_addr_union ip;

                r = extract_first_word(&rvalue, &n, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse Bond ARP ip target address, ignoring assignment: %s",
                                   rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = in_addr_from_string(AF_INET, n, &ip);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Bond ARP ip target address is invalid, ignoring assignment: %s", n);
                        continue;
                }

                r = ordered_set_ensure_allocated(&b->arp_ip_targets, NULL);
                if (r < 0)
                        return log_oom();

                if (ordered_set_size(b->arp_ip_targets) >= NETDEV_BOND_ARP_TARGETS_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Too many ARP ip targets are specified. The maximum number is %d. Ignoring assignment: %s",
                                   NETDEV_BOND_ARP_TARGETS_MAX, n);
                        continue;
                }

                r = ordered_set_put(b->arp_ip_targets, UINT32_TO_PTR(ip.in.s_addr));
                if (r == -EEXIST)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Bond ARP ip target address is duplicated, ignoring assignment: %s", n);
                if (r < 0)
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to store bond ARP ip target address '%s', ignoring assignment: %m", n);
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
        Bond *b = userdata;
        uint16_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou16(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse actor system priority '%s', ignoring: %m", rvalue);
                return 0;
        }

        if (v == 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Failed to parse actor system priority '%s'. Range is [1,65535], ignoring.",
                           rvalue);
                return 0;
        }

        b->ad_actor_sys_prio = v;

        return 0;
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
        Bond *b = userdata;
        uint16_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou16(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse user port key '%s', ignoring: %m", rvalue);
                return 0;
        }

        if (v > 1023) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Failed to parse user port key '%s'. Range is [0…1023], ignoring.", rvalue);
                return 0;
        }

        b->ad_user_port_key = v;

        return 0;
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

        r = ether_addr_from_string(rvalue, &n);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Not a valid MAC address %s. Ignoring assignment: %m",
                           rvalue);
                return 0;
        }
        if (ether_addr_is_null(&n) || (n.ether_addr_octet[0] & 0x01)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Not a valid MAC address %s, can not be null or multicast. Ignoring assignment.",
                           rvalue);
                return 0;
        }

        b->ad_actor_system = n;

        return 0;
}

static void bond_done(NetDev *netdev) {
        Bond *b;

        assert(netdev);
        b = BOND(netdev);
        assert(b);

        ordered_set_free(b->arp_ip_targets);
}

static void bond_init(NetDev *netdev) {
        Bond *b;

        assert(netdev);

        b = BOND(netdev);

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
        .sections = "Match\0NetDev\0Bond\0",
        .fill_message_create = netdev_bond_fill_message_create,
        .create_type = NETDEV_CREATE_MASTER,
        .generate_mac = true,
};
