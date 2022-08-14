/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-netlabel.h"
#include "networkd-network.h"

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

        assert(command != NLBL_UNLABEL_C_UNSPEC && command < __NLBL_UNLABEL_C_MAX);
        assert(address);
        assert(address->link);
        assert(address->link->ifname);
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

        union in_addr_union netmask, masked_addr;
        r = in_addr_prefixlen_to_netmask(address->family, &netmask, address->prefixlen);
        if (r < 0)
                return r;

        /*
         * When adding rules, kernel adds the address to its hash table _applying also the netmask_, but on
         * removal, an exact match is required _without netmask applied_, so apply the mask on both
         * operations.
         */
        masked_addr = address->in_addr;
        r = in_addr_mask(address->family, &masked_addr, address->prefixlen);
        if (r < 0)
                return r;

        if (address->family == AF_INET) {
                r = sd_netlink_message_append_in_addr(m, NLBL_UNLABEL_A_IPV4ADDR, &masked_addr.in);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_in_addr(m, NLBL_UNLABEL_A_IPV4MASK, &netmask.in);
        } else if (address->family == AF_INET6) {
                r = sd_netlink_message_append_in6_addr(m, NLBL_UNLABEL_A_IPV6ADDR, &masked_addr.in6);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_in6_addr(m, NLBL_UNLABEL_A_IPV6MASK, &netmask.in6);
        }
        if (r < 0)
                return r;

        r = netlink_call_async(address->link->manager->genl, NULL, m, netlabel_handler, link_netlink_destroy_callback,
                               address->link);
        if (r < 0)
                return r;

        link_ref(address->link);
        return 0;
}

static const char *get_label(const Address *address) {
        assert(address);
        assert(address->link);

        if (!address->link->network || !IN_SET(address->family, AF_INET, AF_INET6))
                return NULL;

        switch (address->source) {
        case NETWORK_CONFIG_SOURCE_DHCP4:
                return address->link->network->dhcp_netlabel;
        case NETWORK_CONFIG_SOURCE_DHCP6:
                return address->link->network->dhcp6_netlabel;
        case NETWORK_CONFIG_SOURCE_DHCP_PD:
                return address->link->network->dhcp_pd_netlabel;
        case NETWORK_CONFIG_SOURCE_NDISC:
                return address->link->network->ndisc_netlabel;
        case NETWORK_CONFIG_SOURCE_STATIC:
                return address->netlabel;
        default:
                return NULL;
        }
}

void address_add_netlabel(const Address *address) {
        int r;
        const char *label;

        assert(address);

        label = get_label(address);
        if (!label)
                return;

        r = netlabel_command(NLBL_UNLABEL_C_STATICADD, label, address);
        if (r < 0)
                log_link_warning_errno(address->link, r, "Adding NetLabel %s for IP address %s failed, ignoring", label,
                                       IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
        else
                log_link_debug(address->link, "Adding NetLabel %s for IP address %s", label,
                               IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
}

void address_del_netlabel(const Address *address) {
        int r;
        const char *label;

        assert(address);

        label = get_label(address);
        if (!label)
                return;

        r = netlabel_command(NLBL_UNLABEL_C_STATICREMOVE, label, address);
        if (r < 0)
                log_link_warning_errno(address->link, r, "Deleting NetLabel %s for IP address %s failed, ignoring", label,
                                       IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
        else
                log_link_debug(address->link, "Deleting NetLabel %s for IP address %s", label,
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

        char **label = ASSERT_PTR(data);

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(userdata);
        assert(label);

        if (isempty(rvalue)) {
                *label = mfree(*label);
                return 0;
        }

        /* Label semantics depend on LSM but let's do basic checks */
        if (!string_is_safe(rvalue)) {
                _cleanup_free_ char *esc = NULL;

                esc = cescape(rvalue);
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Bad NetLabel label, ignoring: %s", strna(esc));
                return 0;
        }

        return free_and_strdup_warn(label, rvalue);
}
