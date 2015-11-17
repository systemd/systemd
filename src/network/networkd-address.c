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

#include "alloc-util.h"
#include "conf-parser.h"
#include "firewall-util.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"
#include "utf8.h"
#include "util.h"

int address_new(Address **ret) {
        _cleanup_address_free_ Address *address = NULL;

        address = new0(Address, 1);
        if (!address)
                return -ENOMEM;

        address->family = AF_UNSPEC;
        address->scope = RT_SCOPE_UNIVERSE;
        address->cinfo.ifa_prefered = CACHE_INFO_INFINITY_LIFE_TIME;
        address->cinfo.ifa_valid = CACHE_INFO_INFINITY_LIFE_TIME;

        *ret = address;
        address = NULL;

        return 0;
}

int address_new_static(Network *network, unsigned section, Address **ret) {
        _cleanup_address_free_ Address *address = NULL;
        int r;

        if (section) {
                address = hashmap_get(network->addresses_by_section, UINT_TO_PTR(section));
                if (address) {
                        *ret = address;
                        address = NULL;

                        return 0;
                }
        }

        r = address_new(&address);
        if (r < 0)
                return r;

        address->network = network;

        LIST_APPEND(addresses, network->static_addresses, address);

        if (section) {
                address->section = section;
                hashmap_put(network->addresses_by_section,
                            UINT_TO_PTR(address->section), address);
        }

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
                                       UINT_TO_PTR(address->section));
        }

        if (address->link) {
                set_remove(address->link->addresses, address);
                set_remove(address->link->addresses_foreign, address);
        }

        free(address);
}

static void address_hash_func(const void *b, struct siphash *state) {
        const Address *a = b;

        assert(a);

        siphash24_compress(&a->family, sizeof(a->family), state);

        switch (a->family) {
        case AF_INET:
                siphash24_compress(&a->prefixlen, sizeof(a->prefixlen), state);

                /* peer prefix */
                if (a->prefixlen != 0) {
                        uint32_t prefix;

                        if (a->in_addr_peer.in.s_addr != 0)
                                prefix = be32toh(a->in_addr_peer.in.s_addr) >> (32 - a->prefixlen);
                        else
                                prefix = be32toh(a->in_addr.in.s_addr) >> (32 - a->prefixlen);

                        siphash24_compress(&prefix, sizeof(prefix), state);
                }

                /* fallthrough */
        case AF_INET6:
                /* local address */
                siphash24_compress(&a->in_addr, FAMILY_ADDRESS_SIZE(a->family), state);

                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

static int address_compare_func(const void *c1, const void *c2) {
        const Address *a1 = c1, *a2 = c2;

        if (a1->family < a2->family)
                return -1;
        if (a1->family > a2->family)
                return 1;

        switch (a1->family) {
        /* use the same notion of equality as the kernel does */
        case AF_INET:
                if (a1->prefixlen < a2->prefixlen)
                        return -1;
                if (a1->prefixlen > a2->prefixlen)
                        return 1;

                /* compare the peer prefixes */
                if (a1->prefixlen != 0) {
                        /* make sure we don't try to shift by 32.
                         * See ISO/IEC 9899:TC3 § 6.5.7.3. */
                        uint32_t b1, b2;

                        if (a1->in_addr_peer.in.s_addr != 0)
                                b1 = be32toh(a1->in_addr_peer.in.s_addr) >> (32 - a1->prefixlen);
                        else
                                b1 = be32toh(a1->in_addr.in.s_addr) >> (32 - a1->prefixlen);

                        if (a2->in_addr_peer.in.s_addr != 0)
                                b2 = be32toh(a2->in_addr_peer.in.s_addr) >> (32 - a1->prefixlen);
                        else
                                b2 = be32toh(a2->in_addr.in.s_addr) >> (32 - a1->prefixlen);

                        if (b1 < b2)
                                return -1;
                        if (b1 > b2)
                                return 1;
                }

                /* fall-through */
        case AF_INET6:
                return memcmp(&a1->in_addr, &a2->in_addr, FAMILY_ADDRESS_SIZE(a1->family));
        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

static const struct hash_ops address_hash_ops = {
        .hash = address_hash_func,
        .compare = address_compare_func
};

bool address_equal(Address *a1, Address *a2) {
        if (a1 == a2)
                return true;

        if (!a1 || !a2)
                return false;

        return address_compare_func(a1, a2) == 0;
}

static int address_establish(Address *address, Link *link) {
        bool masq;
        int r;

        assert(address);
        assert(link);

        masq = link->network &&
               link->network->ip_masquerade &&
               address->family == AF_INET &&
               address->scope < RT_SCOPE_LINK;

        /* Add firewall entry if this is requested */
        if (address->ip_masquerade_done != masq) {
                union in_addr_union masked = address->in_addr;
                in_addr_mask(address->family, &masked, address->prefixlen);

                r = fw_add_masquerade(masq, AF_INET, 0, &masked, address->prefixlen, NULL, NULL, 0);
                if (r < 0)
                        log_link_warning_errno(link, r, "Could not enable IP masquerading: %m");

                address->ip_masquerade_done = masq;
        }

        return 0;
}

static int address_add_internal(Link *link, Set **addresses,
                                int family,
                                const union in_addr_union *in_addr,
                                unsigned char prefixlen,
                                Address **ret) {
        _cleanup_address_free_ Address *address = NULL;
        int r;

        assert(link);
        assert(addresses);
        assert(in_addr);

        r = address_new(&address);
        if (r < 0)
                return r;

        address->family = family;
        address->in_addr = *in_addr;
        address->prefixlen = prefixlen;
        /* Consider address tentative until we get the real flags from the kernel */
        address->flags = IFA_F_TENTATIVE;

        r = set_ensure_allocated(addresses, &address_hash_ops);
        if (r < 0)
                return r;

        r = set_put(*addresses, address);
        if (r < 0)
                return r;

        address->link = link;

        if (ret)
                *ret = address;

        address = NULL;

        return 0;
}

int address_add_foreign(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret) {
        return address_add_internal(link, &link->addresses_foreign, family, in_addr, prefixlen, ret);
}

int address_add(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret) {
        Address *address;
        int r;

        r = address_get(link, family, in_addr, prefixlen, &address);
        if (r == -ENOENT) {
                /* Address does not exist, create a new one */
                r = address_add_internal(link, &link->addresses, family, in_addr, prefixlen, &address);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Take over a foreign address */
                r = set_ensure_allocated(&link->addresses, &address_hash_ops);
                if (r < 0)
                        return r;

                r = set_put(link->addresses, address);
                if (r < 0)
                        return r;

                set_remove(link->addresses_foreign, address);
        } else if (r == 1) {
                /* Already exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = address;

        return 0;
}

static int address_release(Address *address) {
        int r;

        assert(address);
        assert(address->link);

        /* Remove masquerading firewall entry if it was added */
        if (address->ip_masquerade_done) {
                union in_addr_union masked = address->in_addr;
                in_addr_mask(address->family, &masked, address->prefixlen);

                r = fw_add_masquerade(false, AF_INET, 0, &masked, address->prefixlen, NULL, NULL, 0);
                if (r < 0)
                        log_link_warning_errno(address->link, r, "Failed to disable IP masquerading: %m");

                address->ip_masquerade_done = false;
        }

        return 0;
}

int address_update(Address *address, unsigned char flags, unsigned char scope, struct ifa_cacheinfo *cinfo) {
        bool ready;
        int r;

        assert(address);
        assert(cinfo);

        ready = address_is_ready(address);

        address->flags = flags;
        address->scope = scope;
        address->cinfo = *cinfo;

        if (address->link) {
                link_update_operstate(address->link);

                if (!ready && address_is_ready(address)) {
                        link_check_ready(address->link);

                        if (address->family == AF_INET6 &&
                            in_addr_is_link_local(AF_INET6, &address->in_addr) > 0 &&
                            in_addr_is_null(AF_INET6, (const union in_addr_union*) &address->link->ipv6ll_address) > 0) {
                                r = link_ipv6ll_gained(address->link, &address->in_addr.in6);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return 0;
}

int address_drop(Address *address) {
        Link *link;
        bool ready;

        assert(address);

        ready = address_is_ready(address);
        link = address->link;

        address_release(address);
        address_free(address);

        link_update_operstate(link);

        if (link && !ready)
                link_check_ready(link);

        return 0;
}

int address_get(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret) {
        Address address = {}, *existing;

        assert(link);
        assert(in_addr);
        assert(ret);

        address.family = family;
        address.in_addr = *in_addr;
        address.prefixlen = prefixlen;

        existing = set_get(link->addresses, &address);
        if (existing) {
                *ret = existing;

                return 1;
        } else {
                existing = set_get(link->addresses_foreign, &address);
                if (!existing)
                        return -ENOENT;
        }

        *ret = existing;

        return 0;
}

int address_remove(Address *address, Link *link,
                 sd_netlink_message_handler_t callback) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL;
        int r;

        assert(address);
        assert(address->family == AF_INET || address->family == AF_INET6);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_DELADDR,
                                     link->ifindex, address->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_DELADDR message: %m");

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0)
                return log_error_errno(r, "Could not set prefixlen: %m");

        if (address->family == AF_INET)
                r = sd_netlink_message_append_in_addr(req, IFA_LOCAL, &address->in_addr.in);
        else if (address->family == AF_INET6)
                r = sd_netlink_message_append_in6_addr(req, IFA_LOCAL, &address->in_addr.in6);
        if (r < 0)
                return log_error_errno(r, "Could not append IFA_LOCAL attribute: %m");

        r = sd_netlink_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

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
        if (in_addr_is_null(original->family, &original->in_addr) <= 0)
                return 0;

        /* The address is configured to be 0.0.0.0 or [::] by the user?
         * Then let's acquire something more useful from the pool. */
        r = manager_address_pool_acquire(link->manager, original->family, original->prefixlen, &in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to acquire address from pool: %m");
        if (r == 0) {
                log_link_error(link, "Couldn't find free address for interface, all taken.");
                return -EBUSY;
        }

        if (original->family == AF_INET) {
                /* Pick first address in range for ourselves ... */
                in_addr.in.s_addr = in_addr.in.s_addr | htobe32(1);

                /* .. and use last as broadcast address */
                broadcast.s_addr = in_addr.in.s_addr | htobe32(0xFFFFFFFFUL >> original->prefixlen);
        } else if (original->family == AF_INET6)
                in_addr.in6.s6_addr[15] |= 1;

        r = address_new(&na);
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

int address_configure(Address *address, Link *link, sd_netlink_message_handler_t callback, bool update) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL;
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

        if (update)
                r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &req,
                                                    link->ifindex, address->family);
        else
                r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_NEWADDR,
                                             link->ifindex, address->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_NEWADDR message: %m");

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0)
                return log_error_errno(r, "Could not set prefixlen: %m");

        address->flags |= IFA_F_PERMANENT;

        r = sd_rtnl_message_addr_set_flags(req, (address->flags & 0xff));
        if (r < 0)
                return log_error_errno(r, "Could not set flags: %m");

        if (address->flags & ~0xff) {
                r = sd_netlink_message_append_u32(req, IFA_FLAGS, address->flags);
                if (r < 0)
                        return log_error_errno(r, "Could not set extended flags: %m");
        }

        r = sd_rtnl_message_addr_set_scope(req, address->scope);
        if (r < 0)
                return log_error_errno(r, "Could not set scope: %m");

        if (address->family == AF_INET)
                r = sd_netlink_message_append_in_addr(req, IFA_LOCAL, &address->in_addr.in);
        else if (address->family == AF_INET6)
                r = sd_netlink_message_append_in6_addr(req, IFA_LOCAL, &address->in_addr.in6);
        if (r < 0)
                return log_error_errno(r, "Could not append IFA_LOCAL attribute: %m");

        if (!in_addr_is_null(address->family, &address->in_addr_peer)) {
                if (address->family == AF_INET)
                        r = sd_netlink_message_append_in_addr(req, IFA_ADDRESS, &address->in_addr_peer.in);
                else if (address->family == AF_INET6)
                        r = sd_netlink_message_append_in6_addr(req, IFA_ADDRESS, &address->in_addr_peer.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append IFA_ADDRESS attribute: %m");
        } else {
                if (address->family == AF_INET) {
                        r = sd_netlink_message_append_in_addr(req, IFA_BROADCAST, &address->broadcast);
                        if (r < 0)
                                return log_error_errno(r, "Could not append IFA_BROADCAST attribute: %m");
                }
        }

        if (address->label) {
                r = sd_netlink_message_append_string(req, IFA_LABEL, address->label);
                if (r < 0)
                        return log_error_errno(r, "Could not append IFA_LABEL attribute: %m");
        }

        r = sd_netlink_message_append_cache_info(req, IFA_CACHEINFO,
                                              &address->cinfo);
        if (r < 0)
                return log_error_errno(r, "Could not append IFA_CACHEINFO attribute: %m");

        r = address_establish(address, link);
        if (r < 0)
                return r;

        r = sd_netlink_call_async(link->manager->rtnl, req, callback, link, 0, NULL);
        if (r < 0) {
                address_release(address);
                return log_error_errno(r, "Could not send rtnetlink message: %m");
        }

        link_ref(link);

        r = address_add(link, address->family, &address->in_addr, address->prefixlen, NULL);
        if (r < 0) {
                address_release(address);
                return log_error_errno(r, "Could not add address: %m");
        }

        return 0;
}

int config_parse_broadcast(
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
        _cleanup_address_free_ Address *n = NULL;
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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Broadcast is not valid for IPv6 addresses, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = in_addr_from_string(AF_INET, rvalue, (union in_addr_union*) &n->broadcast);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Broadcast is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->family = AF_INET;
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
        const char *address, *e;
        union in_addr_union buffer;
        int r, f;

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
                        log_syntax(unit, LOG_ERR, filename, line, r, "Prefix length is invalid, ignoring assignment: %s", e + 1);
                        return 0;
                }

                n->prefixlen = (unsigned char) i;

                address = strndupa(rvalue, e - rvalue);
        } else
                address = rvalue;

        r = in_addr_from_string_auto(address, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Address is invalid, ignoring assignment: %s", address);
                return 0;
        }

        if (!e && f == AF_INET) {
                r = in_addr_default_prefixlen(&buffer.in, &n->prefixlen);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Prefix length not specified, and a default one can not be deduced for '%s', ignoring assignment", address);
                        return 0;
                }
        }

        if (n->family != AF_UNSPEC && f != n->family) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Address is incompatible, ignoring assignment: %s", address);
                return 0;
        }

        n->family = f;

        if (streq(lvalue, "Address"))
                n->in_addr = buffer;
        else
                n->in_addr_peer = buffer;

        if (n->family == AF_INET && n->broadcast.s_addr == 0)
                n->broadcast.s_addr = n->in_addr.in.s_addr | htonl(0xfffffffflu >> n->prefixlen);

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
                log_syntax(unit, LOG_ERR, filename, line, 0, "Interface label is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
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

bool address_is_ready(const Address *a) {
        assert(a);

        return !(a->flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED));
}
