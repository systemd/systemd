/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>
#include <linux/if_addrlabel.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "networkd-address-label.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "socket-util.h"

void address_label_free(AddressLabel *label) {
        if (!label)
                return;

        if (label->network) {
                LIST_REMOVE(labels, label->network->address_labels, label);
                assert(label->network->n_address_labels > 0);
                label->network->n_address_labels--;

                if (label->section) {
                        hashmap_remove(label->network->address_labels_by_section, label->section);
                        network_config_section_free(label->section);
                }
        }

        free(label);
}

static int address_label_new_static(Network *network, const char *filename, unsigned section_line, AddressLabel **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(address_label_freep) AddressLabel *label = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                label = hashmap_get(network->address_labels_by_section, n);
                if (label) {
                        *ret = TAKE_PTR(label);

                        return 0;
                }
        }

        label = new(AddressLabel, 1);
        if (!label)
                return -ENOMEM;

        *label = (AddressLabel) {
                .network = network,
        };

        LIST_APPEND(labels, network->address_labels, label);
        network->n_address_labels++;

        if (filename) {
                label->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->address_labels_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->address_labels_by_section, label->section, label);
                if (r < 0)
                        return r;
        }

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
                log_link_warning_errno(link, r, "could not set address label: %m");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->address_label_messages == 0)
                log_link_debug(link, "Addresses label set");

        return 1;
}

int address_label_configure(
                AddressLabel *label,
                Link *link,
                link_netlink_message_handler_t callback,
                bool update) {

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
                return log_error_errno(r, "Could not allocate RTM_NEWADDR message: %m");

        r = sd_rtnl_message_addrlabel_set_prefixlen(req, label->prefixlen);
        if (r < 0)
                return log_error_errno(r, "Could not set prefixlen: %m");

        r = sd_netlink_message_append_u32(req, IFAL_LABEL, label->label);
        if (r < 0)
                return log_error_errno(r, "Could not append IFAL_LABEL attribute: %m");

        r = sd_netlink_message_append_in6_addr(req, IFA_ADDRESS, &label->in_addr.in6);
        if (r < 0)
                return log_error_errno(r, "Could not append IFA_ADDRESS attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               callback ?: address_label_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
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
                return r;

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &n->in_addr, &n->prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Address label is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n = NULL;

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
                return r;

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address label, ignoring: %s", rvalue);
                return 0;
        }

        if (k == 0xffffffffUL) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Address label is invalid, ignoring: %s", rvalue);
                return 0;
        }

        n->label = k;
        n = NULL;

        return 0;
}
