/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/if_addrlabel.h>

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-address-label.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"

AddressLabel *address_label_free(AddressLabel *label) {
        if (!label)
                return NULL;

        if (label->network) {
                assert(label->section);
                hashmap_remove(label->network->address_labels_by_section, label->section);
        }

        network_config_section_free(label->section);
        return mfree(label);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(AddressLabel, address_label_free);

static int address_label_new_static(Network *network, const char *filename, unsigned section_line, AddressLabel **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(address_label_freep) AddressLabel *label = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        label = hashmap_get(network->address_labels_by_section, n);
        if (label) {
                *ret = TAKE_PTR(label);
                return 0;
        }

        label = new(AddressLabel, 1);
        if (!label)
                return -ENOMEM;

        *label = (AddressLabel) {
                .network = network,
                .section = TAKE_PTR(n),
        };

        r = hashmap_ensure_put(&network->address_labels_by_section, &network_config_hash_ops, label->section, label);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(label);
        return 0;
}

static int address_label_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->address_label_messages > 0);

        link->address_label_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set address label");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->address_label_messages == 0)
                log_link_debug(link, "Addresses label set");

        return 1;
}

static int address_label_configure(AddressLabel *label, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(label);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_addrlabel(link->manager->rtnl, &req, RTM_NEWADDRLABEL,
                                          link->ifindex, AF_INET6);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_NEWADDR message: %m");

        r = sd_rtnl_message_addrlabel_set_prefixlen(req, label->prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set prefixlen: %m");

        r = sd_netlink_message_append_u32(req, IFAL_LABEL, label->label);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFAL_LABEL attribute: %m");

        r = sd_netlink_message_append_in6_addr(req, IFA_ADDRESS, &label->in_addr.in6);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_ADDRESS attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               address_label_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int link_set_address_labels(Link *link) {
        AddressLabel *label;
        int r;

        assert(link);
        assert(link->network);

        HASHMAP_FOREACH(label, link->network->address_labels_by_section) {
                r = address_label_configure(label, link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set address label: %m");

                link->address_label_messages++;
        }

        return 0;
}

void network_drop_invalid_address_labels(Network *network) {
        AddressLabel *label;

        assert(network);

        HASHMAP_FOREACH(label, network->address_labels_by_section)
                if (section_is_invalid(label->section))
                        address_label_free(label);
}

int config_parse_address_label_prefix(const char *unit,
                                      const char *filename,
                                      unsigned line,
                                      const char *section,
                                      unsigned section_line,
                                      const char *lvalue,
                                      int ltype,
                                      const char *rvalue,
                                      void *data,
                                      void *userdata) {

        _cleanup_(address_label_free_or_set_invalidp) AddressLabel *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_label_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &n->in_addr, &n->prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Address label is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_address_label(
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

        _cleanup_(address_label_free_or_set_invalidp) AddressLabel *n = NULL;
        Network *network = userdata;
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_label_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse address label, ignoring: %s", rvalue);
                return 0;
        }

        if (k == 0xffffffffUL) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Address label is invalid, ignoring: %s", rvalue);
                return 0;
        }

        n->label = k;
        TAKE_PTR(n);

        return 0;
}
