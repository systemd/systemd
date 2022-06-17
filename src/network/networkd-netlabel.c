/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-netlabel.h"
#include "networkd-network.h"

int netlabels_dup(Address *address, Set *netlabels) {
        const char *label;
        int r;

        assert(address);

        address->netlabels = set_free(address->netlabels);

        SET_FOREACH(label, netlabels) {
                r = set_put_strdup(&address->netlabels, label);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netlabel_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert_se(rtnl);
        assert_se(m);
        assert_se(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_message_warning_errno(link, m, r, "NetLabel operation failed, ignoring");
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
        assert(IN_SET(address->family, AF_INET, AF_INET6));

        r = sd_genl_message_new(address->link->manager->genl, NETLBL_NLTYPE_UNLABELED_NAME, command, &m);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NLBL_UNLABEL_A_IFACE, address->link->ifname);
        if (r < 0)
                return r;

        if (command == NLBL_UNLABEL_C_STATICADD) {
                assert(label);
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

        r = netlink_call_async(address->link->manager->genl, NULL, m, netlabel_handler,
                               link_netlink_destroy_callback, address->link);
        if (r < 0)
                return r;

        link_ref(address->link);
        return 0;
}

void address_add_netlabels(const Address *address) {
        const char *label;
        int r;

        assert(address);
        assert(address->link);

        SET_FOREACH(label, address->netlabels) {
                r = netlabel_command(NLBL_UNLABEL_C_STATICADD, label, address);
                if (r < 0)
                        log_link_warning_errno(address->link, r,
                                               "Failed to add NetLabel %s for IP address %s, ignoring: %m",
                                               label,
                                               IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
                else
                        log_link_debug(address->link,
                                       "Adding NetLabel %s for IP address %s",
                                       label,
                                       IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
        }
}

void address_del_netlabels(const Address *address) {
        int r;

        assert(address);
        assert(address->link);

        r = netlabel_command(NLBL_UNLABEL_C_STATICREMOVE, NULL, address);
        if (r < 0)
                log_link_warning_errno(address->link, r,
                                       "Failed to delete NetLabels for IP address %s, ignoring: %m",
                                       IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
        else
                log_link_debug(address->link,
                               "Deleting NetLabels for IP address %s",
                               IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
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
                void *userdata) {

        Set **set = ASSERT_PTR(data);
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
                                   "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                /* Label semantics depend on LSM but let's do basic checks */
                if (!string_is_safe(w)) {
                        _cleanup_free_ char *esc = NULL;

                        esc = cescape(w);
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Bad NetLabel label, ignoring: %s", strna(esc));
                        continue;
                }

                r = set_ensure_consume(set, &string_hash_ops_free, TAKE_PTR(w));
                if (r < 0)
                        return log_oom();
        }
}
