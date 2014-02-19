/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <net/if.h>

#include "networkd.h"

#include "utf8.h"
#include "util.h"
#include "conf-parser.h"
#include "net-util.h"

int address_new_static(Network *network, unsigned section, Address **ret) {
        _cleanup_address_free_ Address *address = NULL;

        if (section) {
                uint64_t key = section;
                address = hashmap_get(network->addresses_by_section, &key);
                if (address) {
                        *ret = address;
                        address = NULL;

                        return 0;
                }
        }

        address = new0(Address, 1);
        if (!address)
                return -ENOMEM;

        address->family = AF_UNSPEC;

        address->network = network;

        LIST_PREPEND(static_addresses, network->static_addresses, address);

        if (section) {
                address->section = section;
                hashmap_put(network->addresses_by_section, &address->section, address);
        }

        *ret = address;
        address = NULL;

        return 0;
}

int address_new_dynamic(Address **ret) {
        _cleanup_address_free_ Address *address = NULL;

        address = new0(Address, 1);
        if (!address)
                return -ENOMEM;

        address->family = AF_UNSPEC;

        *ret = address;
        address = NULL;

        return 0;
}

void address_free(Address *address) {
        if (!address)
                return;

        if (address->network) {
                LIST_REMOVE(static_addresses, address->network->static_addresses, address);

                if (address->section)
                        hashmap_remove(address->network->addresses_by_section,
                                       &address->section);
        }

        free(address);
}

int address_drop(Address *address, Link *link,
                 sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(address);
        assert(address->family == AF_INET || address->family == AF_INET6);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_DELADDR,
                                     link->ifindex, address->family);
        if (r < 0) {
                log_error("Could not allocate RTM_DELADDR message: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0) {
                log_error("Could not set prefixlen: %s", strerror(-r));
                return r;
        }

        if (address->family == AF_INET)
                r = sd_rtnl_message_append_in_addr(req, IFA_LOCAL, &address->in_addr.in);
        else if (address->family == AF_INET6)
                r = sd_rtnl_message_append_in6_addr(req, IFA_LOCAL, &address->in_addr.in6);
        if (r < 0) {
                log_error("Could not append IFA_LOCAL attribute: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        return 0;
}

int address_configure(Address *address, Link *link,
                      sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(address);
        assert(address->family == AF_INET || address->family == AF_INET6);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_NEWADDR,
                                     link->ifindex, address->family);
        if (r < 0) {
                log_error("Could not allocate RTM_NEWADDR message: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0) {
                log_error("Could not set prefixlen: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_addr_set_flags(req, IFA_F_PERMANENT);
        if (r < 0) {
                log_error("Could not set flags: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_addr_set_scope(req, RT_SCOPE_UNIVERSE);
        if (r < 0) {
                log_error("Could not set scope: %s", strerror(-r));
                return r;
        }

        if (address->family == AF_INET)
                r = sd_rtnl_message_append_in_addr(req, IFA_LOCAL, &address->in_addr.in);
        else if (address->family == AF_INET6)
                r = sd_rtnl_message_append_in6_addr(req, IFA_LOCAL, &address->in_addr.in6);
        if (r < 0) {
                log_error("Could not append IFA_LOCAL attribute: %s",
                          strerror(-r));
                return r;
        }

        if (address->family == AF_INET) {
                r = sd_rtnl_message_append_in_addr(req, IFA_BROADCAST, &address->broadcast);
                if (r < 0) {
                        log_error("Could not append IFA_BROADCAST attribute: %s",
                                  strerror(-r));
                        return r;
                }
        }

        if (address->label) {
                r = sd_rtnl_message_append_string(req, IFA_LABEL, address->label);
                if (r < 0) {
                        log_error("Could not append IFA_LABEL attribute: %s",
                                  strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        return 0;
}

int config_parse_dns(const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        Address **dns = data;
        _cleanup_address_free_ Address *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_dynamic(&n);
        if (r < 0)
                return r;

        r = net_parse_inaddr(rvalue, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "DNS address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        *dns = n;
        n = NULL;

        return 0;
}

int config_parse_broadcast(const char *unit,
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
        _cleanup_address_free_ Address *n = NULL;
        _cleanup_free_ char *address = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        if (n->family == AF_INET6) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Broadcast is not valid for IPv6 addresses, "
                           "ignoring assignment: %s", address);
                return 0;
        }

        r = net_parse_inaddr(address, &n->family, &n->broadcast);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Broadcast is invalid, ignoring assignment: %s", address);
                return 0;
        }

        n = NULL;

        return 0;
}

int config_parse_address(const char *unit,
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
        _cleanup_address_free_ Address *n = NULL;
        _cleanup_free_ char *address = NULL;
        const char *e;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "Network")) {
                /* we are not in an Address section, so treat
                 * this as the special '0' section */
                section_line = 0;
        }

        r = address_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        /* Address=address/prefixlen */

        /* prefixlen */
        e = strchr(rvalue, '/');
        if (e) {
                unsigned i;
                r = safe_atou(e + 1, &i);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Interface prefix length is invalid, "
                                   "ignoring assignment: %s", e + 1);
                        return 0;
                }

                n->prefixlen = (unsigned char) i;

                address = strndup(rvalue, e - rvalue);
                if (!address)
                        return log_oom();
        } else {
                address = strdup(rvalue);
                if (!address)
                        return log_oom();
        }

        r = net_parse_inaddr(address, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Address is invalid, ignoring assignment: %s", address);
                return 0;
        }

        if (n->family == AF_INET && !n->broadcast.s_addr)
                n->broadcast.s_addr = n->in_addr.in.s_addr |
                                      htonl(0xfffffffflu >> n->prefixlen);

        n = NULL;

        return 0;
}

int config_parse_label(const char *unit,
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
        _cleanup_address_free_ Address *n = NULL;
        char *label;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, section_line, &n);
        if (r < 0)
                return r;

        label = strdup(rvalue);
        if (!label)
                return log_oom();

        if (!ascii_is_valid(label) || strlen(label) >= IFNAMSIZ) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Interface label is not ASCII clean or is too"
                           " long, ignoring assignment: %s", rvalue);
                free(label);
                return 0;
        }

        free(n->label);
        if (*label)
                n->label = label;
        else {
                free(label);
                n->label = NULL;
        }

        n = NULL;

        return 0;
}
