/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-netlabel.h"
#include "networkd-network.h"

static int netlabel_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        int r;

        assert_se(rtnl);
        assert_se(m);
        assert_se(userdata);

        Link *link = userdata;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_warning_errno(link, r, "NetLabel operation failed: %m");
                return 1;
        }

        log_link_debug(link, "NetLabel operation successful");

        return 1;
}

static int netlabel_command(uint16_t command, const char *label, const Address *address) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(address);
        assert(address->link);
        assert(address->link->manager);
        assert(address->link->manager->genl);
        assert(address->link->network);
        assert(IN_SET(address->family, AF_INET, AF_INET6));

        r = sd_genl_message_new(address->link->manager->genl, NETLBL_NLTYPE_UNLABELED_NAME, command, &m);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NLBL_UNLABEL_A_IFACE, address->link->ifname);
        if (r < 0)
                return r;

        if (command == NLBL_UNLABEL_C_STATICADD) {
                r = sd_netlink_message_append_string(m, NLBL_UNLABEL_A_SECCTX, label);
                if (r < 0)
                        return r;
        }

        union in_addr_union netmask;

        r = in_addr_prefixlen_to_netmask(address->family, &netmask, address->prefixlen);
        if (r < 0)
                return r;

        if (address->family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, NLBL_UNLABEL_A_IPV4ADDR, &address->in_addr.in);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_in_addr(m, NLBL_UNLABEL_A_IPV4MASK, &netmask.in);
        } else if (address->family == AF_INET6) {
                r = sd_netlink_message_append_in6_addr(m, NLBL_UNLABEL_A_IPV6ADDR, &address->in_addr.in6);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_in6_addr(m, NLBL_UNLABEL_A_IPV6MASK, &netmask.in6);
        }
        if (r < 0)
                return r;

        return sd_netlink_call_async(address->link->manager->genl, NULL, m, netlabel_handler, NULL, address->link, 0, NULL);
}

static void address_add_netlabel_set(const Address *address, Set *labels) {
        _cleanup_free_ char *addr_str = NULL;
        int r;
        const char *label;

        (void) in_addr_prefix_to_string(address->family, &address->in_addr, address->prefixlen, &addr_str);

        SET_FOREACH(label, labels) {
                r = netlabel_command(NLBL_UNLABEL_C_STATICADD, label, address);
                if (r < 0)
                        log_link_warning_errno(address->link, r, "Adding NetLabel %s for IP address %s failed, ignoring: %m",
                                               label, strna(addr_str));
                log_link_debug(address->link, "Added NetLabel %s for IP address %s",
                               label, strna(addr_str));
        }
}

void address_add_netlabel(const Address *address) {
        assert(address);
        assert(address->link);

        if (!address->link->network || !IN_SET(address->family, AF_INET, AF_INET6))
                return;

        if (address->family == AF_INET && IN_SET(address->source, NETWORK_CONFIG_SOURCE_DHCP4, NETWORK_CONFIG_SOURCE_DHCP_PD) && address->link->network->dhcp4_netlabels)
                address_add_netlabel_set(address, address->link->network->dhcp4_netlabels);
        else if (address->family == AF_INET6 && IN_SET(address->source, NETWORK_CONFIG_SOURCE_DHCP6, NETWORK_CONFIG_SOURCE_DHCP_PD) && address->link->network->dhcp6_netlabels)
                address_add_netlabel_set(address, address->link->network->dhcp6_netlabels);
        else if (IN_SET(address->source, NETWORK_CONFIG_SOURCE_STATIC))
                address_add_netlabel_set(address, address->netlabels);
}

void address_del_netlabel(const Address *address) {
        int r;
        _cleanup_free_ char *addr_str = NULL;

        assert(address);
        assert(address->link);

        if (!address->link->network || !IN_SET(address->family, AF_INET, AF_INET6))
                return;

        (void) in_addr_prefix_to_string(address->family, &address->in_addr, address->prefixlen, &addr_str);

        r = netlabel_command(NLBL_UNLABEL_C_STATICREMOVE, NULL, address);
        if (r < 0)
                log_link_warning_errno(address->link, r, "Deleting NetLabels for IP address %s failed, ignoring: %m",
                                       strna(addr_str));
        log_link_debug(address->link, "Deleted NetLabels for IP address %s",
                       strna(addr_str));
}

int config_parse_netlabel(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                Set **set) {
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *set = set_free(*set);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract NetLabel label, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                /* Label semantics depend on LSM but let's do basic checks */
                if (!string_is_safe(w)) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Bad NetLabel label, ignoring: %s", rvalue);
                        return 0;
                }

                r = set_ensure_consume(set, &string_hash_ops, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_dhcp_or_ra_netlabel(
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
        Network *network = userdata;

        assert(network);
        assert(filename);
        assert(lvalue);
        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));
        assert(rvalue);
        assert(data);

        Set **set;

        switch (ltype) {
        case AF_INET:
                set = &network->dhcp4_netlabels;
                break;
        case AF_INET6:
                set = &network->dhcp6_netlabels;
                break;
        default:
                assert_not_reached();
        }

        return config_parse_netlabel(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, set);
}
