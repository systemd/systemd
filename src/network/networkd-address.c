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
#include "network-internal.h"

static void address_init(Address *address) {
        assert(address);

        address->family = AF_UNSPEC;
        address->scope = RT_SCOPE_UNIVERSE;
        address->cinfo.ifa_prefered = CACHE_INFO_INFINITY_LIFE_TIME;
        address->cinfo.ifa_valid = CACHE_INFO_INFINITY_LIFE_TIME;
}

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

        address_init(address);

        address->network = network;

        LIST_PREPEND(addresses, network->static_addresses, address);

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

        address_init(address);

        *ret = address;
        address = NULL;

        return 0;
}

void address_free(Address *address) {
        if (!address)
                return;

        if (address->network) {
                LIST_REMOVE(addresses, address->network->static_addresses, address);

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

        link_ref(link);

        return 0;
}

int address_update(Address *address, Link *link,
                   sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        assert(address);
        assert(address->family == AF_INET || address->family == AF_INET6);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &req,
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

        r = sd_rtnl_message_addr_set_scope(req, address->scope);
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

        r = sd_rtnl_message_append_cache_info(req, IFA_CACHEINFO, &address->cinfo);
        if (r < 0) {
                log_error("Could not append IFA_CACHEINFO attribute: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link_ref(link);

        return 0;
}

static int address_acquire(Link *link, Address *original, Address **ret) {
        union in_addr_union in_addr = {};
        struct in_addr broadcast = {};
        _cleanup_address_free_ Address *na = NULL;
        int r;

        assert(link);
        assert(original);
        assert(ret);

        /* Something useful was configured? just use it */
        if (in_addr_null(original->family, &original->in_addr) <= 0)
                return 0;

        /* The address is configured to be 0.0.0.0 or [::] by the user?
         * Then let's acquire something more useful from the pool. */
        r = manager_address_pool_acquire(link->manager, original->family, original->prefixlen, &in_addr);
        if (r < 0) {
                log_error_link(link, "Failed to acquire address from pool: %s", strerror(-r));
                return r;
        }
        if (r == 0) {
                log_error_link(link, "Couldn't find free address for interface, all taken.");
                return -EBUSY;
        }

        if (original->family == AF_INET) {
                /* Pick first address in range for ourselves ...*/
                in_addr.in.s_addr = in_addr.in.s_addr | htobe32(1);

                /* .. and use last as broadcast address */
                broadcast.s_addr = in_addr.in.s_addr | htobe32(0xFFFFFFFFUL >> original->prefixlen);
        } else if (original->family == AF_INET6)
                in_addr.in6.s6_addr[15] |= 1;

        r = address_new_dynamic(&na);
        if (r < 0)
                return r;

        na->family = original->family;
        na->prefixlen = original->prefixlen;
        na->scope = original->scope;
        na->cinfo = original->cinfo;

        if (original->label) {
                na->label = strdup(original->label);
                if (!na->label)
                        return -ENOMEM;
        }

        na->broadcast = broadcast;
        na->in_addr = in_addr;

        LIST_PREPEND(addresses, link->pool_addresses, na);

        *ret = na;
        na = NULL;

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

        r = address_acquire(link, address, &address);
        if (r < 0)
                return r;

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

        r = sd_rtnl_message_addr_set_scope(req, address->scope);
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

        r = sd_rtnl_message_append_cache_info(req, IFA_CACHEINFO,
                                              &address->cinfo);
        if (r < 0) {
                log_error("Could not append IFA_CACHEINFO attribute: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        link_ref(link);

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
        Network *network = userdata;
        Address *tail;
        _cleanup_address_free_ Address *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(network);

        r = address_new_dynamic(&n);
        if (r < 0)
                return r;

        r = net_parse_inaddr(rvalue, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "DNS address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (streq(lvalue, "DNS")) {
                LIST_FIND_TAIL(addresses, network->dns, tail);
                LIST_INSERT_AFTER(addresses, network->dns, tail, n);
        } else if (streq(lvalue, "NTP")) {
                LIST_FIND_TAIL(addresses, network->ntp, tail);
                LIST_INSERT_AFTER(addresses, network->ntp, tail, n);
        } else {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Key is invalid, ignoring assignment: %s=%s", lvalue, rvalue);
                return 0;
        }

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

bool address_equal(Address *a1, Address *a2) {
        /* same object */
        if (a1 == a2)
                return true;

        /* one, but not both, is NULL */
        if (!a1 || !a2)
                return false;

        if (a1->family != a2->family)
                return false;

        switch (a1->family) {
        /* use the same notion of equality as the kernel does */
        case AF_UNSPEC:
                return true;

        case AF_INET:
                if (a1->prefixlen != a2->prefixlen)
                        return false;
                else {
                        uint32_t b1, b2;

                        b1 = be32toh(a1->in_addr.in.s_addr);
                        b2 = be32toh(a2->in_addr.in.s_addr);

                        return (b1 >> (32 - a1->prefixlen)) == (b2 >> (32 - a1->prefixlen));
                }

        case AF_INET6:
        {
                uint64_t *b1, *b2;

                b1 = (uint64_t*)&a1->in_addr.in6;
                b2 = (uint64_t*)&a2->in_addr.in6;

                return (((b1[0] ^ b2[0]) | (b1[1] ^ b2[1])) == 0UL);
        }
        default:
                assert_not_reached("Invalid address family");
        }
}
