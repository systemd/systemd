/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "dns-domain.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "networkd-radv.h"
#include "parse-util.h"
#include "sd-radv.h"
#include "string-util.h"
#include "string-table.h"
#include "strv.h"

void prefix_free(Prefix *prefix) {
        if (!prefix)
                return;

        if (prefix->network) {
                LIST_REMOVE(prefixes, prefix->network->static_prefixes, prefix);
                assert(prefix->network->n_static_prefixes > 0);
                prefix->network->n_static_prefixes--;

                if (prefix->section)
                        hashmap_remove(prefix->network->prefixes_by_section,
                                       prefix->section);
        }

        network_config_section_free(prefix->section);
        prefix->radv_prefix = sd_radv_prefix_unref(prefix->radv_prefix);

        free(prefix);
}

int prefix_new(Prefix **ret) {
        _cleanup_(prefix_freep) Prefix *prefix = NULL;

        prefix = new0(Prefix, 1);
        if (!prefix)
                return -ENOMEM;

        if (sd_radv_prefix_new(&prefix->radv_prefix) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(prefix);

        return 0;
}

static int prefix_new_static(Network *network, const char *filename,
                             unsigned section_line, Prefix **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(prefix_freep) Prefix *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                if (section_line) {
                        prefix = hashmap_get(network->prefixes_by_section, n);
                        if (prefix) {
                                *ret = TAKE_PTR(prefix);

                                return 0;
                        }
                }
        }

        r = prefix_new(&prefix);
        if (r < 0)
                return r;

        prefix->network = network;
        LIST_APPEND(prefixes, network->static_prefixes, prefix);
        network->n_static_prefixes++;

        if (filename) {
                prefix->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->prefixes_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->prefixes_by_section, prefix->section, prefix);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(prefix);

        return 0;
}

int route_prefix_new(Prefix **ret) {
        _cleanup_(prefix_freep) Prefix *prefix = NULL;

        prefix = new0(Prefix, 1);
        if (!prefix)
                return -ENOMEM;

        if (sd_radv_route_prefix_new(&prefix->radv_route_prefix) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(prefix);

        return 0;
}

void route_prefix_free(Prefix *prefix) {
        if (!prefix)
                return;

        if (prefix->network) {
                LIST_REMOVE(prefixes, prefix->network->static_route_prefixes, prefix);
                assert(prefix->network->n_static_route_prefixes > 0);
                prefix->network->n_static_route_prefixes--;

                if (prefix->section)
                        hashmap_remove(prefix->network->route_prefixes_by_section,
                                       prefix->section);
        }

        network_config_section_free(prefix->section);

        free(prefix);
}

static int route_prefix_new_static(Network *network, const char *filename,
                                   unsigned section_line, Prefix **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(prefix_freep) Prefix *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                if (section_line) {
                        prefix = hashmap_get(network->route_prefixes_by_section, n);
                        if (prefix) {
                                *ret = TAKE_PTR(prefix);

                                return 0;
                        }
                }
        }

        r = route_prefix_new(&prefix);
        if (r < 0)
                return r;

        prefix->network = network;
        LIST_APPEND(prefixes, network->static_route_prefixes, prefix);
        network->n_static_route_prefixes++;

        if (filename) {
                prefix->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->route_prefixes_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->route_prefixes_by_section, prefix->section, prefix);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(prefix);

        return 0;
}

int config_parse_prefix(const char *unit,
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        uint8_t prefixlen = 64;
        union in_addr_union in6addr;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return r;

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &in6addr, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (sd_radv_prefix_set_prefix(p->radv_prefix, &in6addr.in6, prefixlen) < 0)
                return -EADDRNOTAVAIL;

        log_syntax(unit, LOG_INFO, filename, line, r, "Found prefix %s", rvalue);

        p = NULL;

        return 0;
}

int config_parse_prefix_flags(const char *unit,
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        int r, val;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return r;

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse address flag, ignoring: %s", rvalue);
                return 0;
        }

        val = r;

        if (streq(lvalue, "OnLink"))
                r = sd_radv_prefix_set_onlink(p->radv_prefix, val);
        else if (streq(lvalue, "AddressAutoconfiguration"))
                r = sd_radv_prefix_set_address_autoconfiguration(p->radv_prefix, val);
        if (r < 0)
                return r;

        p = NULL;

        return 0;
}

int config_parse_prefix_lifetime(const char *unit,
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return r;

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        /* a value of 0xffffffff represents infinity */
        if (streq(lvalue, "PreferredLifetimeSec"))
                r = sd_radv_prefix_set_preferred_lifetime(p->radv_prefix,
                                                          DIV_ROUND_UP(usec, USEC_PER_SEC));
        else if (streq(lvalue, "ValidLifetimeSec"))
                r = sd_radv_prefix_set_valid_lifetime(p->radv_prefix,
                                                      DIV_ROUND_UP(usec, USEC_PER_SEC));
        if (r < 0)
                return r;

        p = NULL;

        return 0;
}

int config_parse_route_prefix(const char *unit,
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        uint8_t prefixlen = 64;
        union in_addr_union in6addr;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return r;

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &in6addr, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Route prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (sd_radv_prefix_set_route_prefix(p->radv_route_prefix, &in6addr.in6, prefixlen) < 0)
                return -EADDRNOTAVAIL;

        log_syntax(unit, LOG_INFO, filename, line, r, "Found route prefix %s", rvalue);

        p = NULL;

        return 0;
}

int config_parse_route_prefix_lifetime(const char *unit,
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return r;

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Roure lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        /* a value of 0xffffffff represents infinity */
        r = sd_radv_route_prefix_set_lifetime(p->radv_route_prefix, DIV_ROUND_UP(usec, USEC_PER_SEC));
        if (r < 0)
                return r;

        p = NULL;

        return 0;
}

static int radv_get_ip6dns(Network *network, struct in6_addr **dns,
                           size_t *n_dns) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        size_t i, n_addresses = 0, n_allocated = 0;

        assert(network);
        assert(dns);
        assert(n_dns);

        for (i = 0; i < network->n_dns; i++) {
                union in_addr_union *addr;

                if (network->dns[i].family != AF_INET6)
                        continue;

                addr = &network->dns[i].address;

                if (in_addr_is_null(AF_INET6, addr) ||
                    in_addr_is_link_local(AF_INET6, addr) ||
                    in_addr_is_localhost(AF_INET6, addr))
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return -ENOMEM;

                addresses[n_addresses++] = addr->in6;
        }

        if (addresses) {
                *dns = TAKE_PTR(addresses);

                *n_dns = n_addresses;
        }

        return n_addresses;
}

static int radv_set_dns(Link *link, Link *uplink) {
        _cleanup_free_ struct in6_addr *dns = NULL;
        size_t n_dns;
        usec_t lifetime_usec;
        int r;

        if (!link->network->router_emit_dns)
                return 0;

        if (link->network->router_dns) {
                dns = newdup(struct in6_addr, link->network->router_dns,
                             link->network->n_router_dns);
                if (!dns)
                        return -ENOMEM;

                n_dns = link->network->n_router_dns;
                lifetime_usec = link->network->router_dns_lifetime_usec;

                goto set_dns;
        }

        lifetime_usec = SD_RADV_DEFAULT_DNS_LIFETIME_USEC;

        r = radv_get_ip6dns(link->network, &dns, &n_dns);
        if (r > 0)
                goto set_dns;

        if (uplink) {
                if (!uplink->network) {
                        log_link_debug(uplink, "Cannot fetch DNS servers as uplink interface is not managed by us");
                        return 0;
                }

                r = radv_get_ip6dns(uplink->network, &dns, &n_dns);
                if (r > 0)
                        goto set_dns;
        }

        return 0;

 set_dns:
        return sd_radv_set_rdnss(link->radv,
                                 DIV_ROUND_UP(lifetime_usec, USEC_PER_SEC),
                                 dns, n_dns);
}

static int radv_set_domains(Link *link, Link *uplink) {
        OrderedSet *search_domains;
        usec_t lifetime_usec;
        _cleanup_free_ char **s = NULL; /* just free() because the strings are owned by the set */

        if (!link->network->router_emit_domains)
                return 0;

        search_domains = link->network->router_search_domains;
        lifetime_usec = link->network->router_dns_lifetime_usec;

        if (search_domains)
                goto set_domains;

        lifetime_usec = SD_RADV_DEFAULT_DNS_LIFETIME_USEC;

        search_domains = link->network->search_domains;
        if (search_domains)
                goto set_domains;

        if (uplink) {
                if (!uplink->network) {
                        log_link_debug(uplink, "Cannot fetch DNS search domains as uplink interface is not managed by us");
                        return 0;
                }

                search_domains = uplink->network->search_domains;
                if (search_domains)
                        goto set_domains;
        }

        return 0;

 set_domains:
        s = ordered_set_get_strv(search_domains);
        if (!s)
                return log_oom();

        return sd_radv_set_dnssl(link->radv,
                                 DIV_ROUND_UP(lifetime_usec, USEC_PER_SEC),
                                 s);

}

int radv_emit_dns(Link *link) {
        Link *uplink;
        int r;

        uplink = manager_find_uplink(link->manager, link);

        r = radv_set_dns(link, uplink);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set RA DNS: %m");

        r = radv_set_domains(link, uplink);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not set RA Domains: %m");

        return 0;
}

int radv_configure(Link *link) {
        int r;
        Prefix *p;

        assert(link);
        assert(link->network);

        r = sd_radv_new(&link->radv);
        if (r < 0)
                return r;

        r = sd_radv_attach_event(link->radv, NULL, 0);
        if (r < 0)
                return r;

        r = sd_radv_set_mac(link->radv, &link->mac);
        if (r < 0)
                return r;

        r = sd_radv_set_ifindex(link->radv, link->ifindex);
        if (r < 0)
                return r;

        r = sd_radv_set_managed_information(link->radv, link->network->router_managed);
        if (r < 0)
                return r;

        r = sd_radv_set_other_information(link->radv, link->network->router_other_information);
        if (r < 0)
                return r;

        /* a value of 0xffffffff represents infinity, 0x0 means this host is
           not a router */
        r = sd_radv_set_router_lifetime(link->radv,
                                        DIV_ROUND_UP(link->network->router_lifetime_usec, USEC_PER_SEC));
        if (r < 0)
                return r;

        if (link->network->router_lifetime_usec > 0) {
                r = sd_radv_set_preference(link->radv,
                                           link->network->router_preference);
                if (r < 0)
                        return r;
        }

        if (IN_SET(link->network->router_prefix_delegation,
                   RADV_PREFIX_DELEGATION_STATIC,
                   RADV_PREFIX_DELEGATION_BOTH)) {

                LIST_FOREACH(prefixes, p, link->network->static_prefixes) {
                        r = sd_radv_add_prefix(link->radv, p->radv_prefix, false);
                        if (r == -EEXIST)
                                continue;
                        if (r == -ENOEXEC) {
                                log_link_warning_errno(link, r, "[IPv6Prefix] section configured without Prefix= setting, ignoring section.");
                                continue;
                        }
                        if (r < 0)
                                return r;
                }

                LIST_FOREACH(prefixes, p, link->network->static_route_prefixes) {
                        r = sd_radv_add_route_prefix(link->radv, p->radv_route_prefix, false);
                        if (r == -EEXIST)
                                continue;
                        if (r < 0)
                                return r;
                }

        }

        return radv_emit_dns(link);
}

int config_parse_radv_dns(
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

        Network *n = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL;
                union in_addr_union a;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                if (in_addr_from_string(AF_INET6, w, &a) >= 0) {
                        struct in6_addr *m;

                        m = reallocarray(n->router_dns, n->n_router_dns + 1, sizeof(struct in6_addr));
                        if (!m)
                                return log_oom();

                        m[n->n_router_dns++] = a.in6;
                        n->router_dns = m;

                } else
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse DNS server address, ignoring: %s", w);
        }

        return 0;
}

int config_parse_radv_search_domains(
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

        Network *n = data;
        const char *p = rvalue;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *w = NULL, *idna = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = dns_name_apply_idna(w, &idna);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to apply IDNA to domain name '%s', ignoring: %m", w);
                        continue;
                } else if (r == 0)
                        /* transfer ownership to simplify subsequent operations */
                        idna = TAKE_PTR(w);

                r = ordered_set_ensure_allocated(&n->router_search_domains, &string_hash_ops);
                if (r < 0)
                        return r;

                r = ordered_set_consume(n->router_search_domains, TAKE_PTR(idna));
                if (r < 0)
                        return r;
        }

        return 0;
}

static const char * const radv_prefix_delegation_table[_RADV_PREFIX_DELEGATION_MAX] = {
        [RADV_PREFIX_DELEGATION_NONE] = "no",
        [RADV_PREFIX_DELEGATION_STATIC] = "static",
        [RADV_PREFIX_DELEGATION_DHCP6] = "dhcpv6",
        [RADV_PREFIX_DELEGATION_BOTH] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(
                radv_prefix_delegation,
                RADVPrefixDelegation,
                RADV_PREFIX_DELEGATION_BOTH);

int config_parse_router_prefix_delegation(
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
        RADVPrefixDelegation d;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        d = radv_prefix_delegation_from_string(rvalue);
        if (d < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -EINVAL, "Invalid router prefix delegation '%s', ignoring assignment.", rvalue);
                return 0;
        }

        network->router_prefix_delegation = d;

        return 0;
}

int config_parse_router_preference(const char *unit,
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

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "high"))
                network->router_preference = SD_NDISC_PREFERENCE_HIGH;
        else if (STR_IN_SET(rvalue, "medium", "normal", "default"))
                network->router_preference = SD_NDISC_PREFERENCE_MEDIUM;
        else if (streq(rvalue, "low"))
                network->router_preference = SD_NDISC_PREFERENCE_LOW;
        else
                log_syntax(unit, LOG_ERR, filename, line, -EINVAL, "Router preference '%s' is invalid, ignoring assignment: %m", rvalue);

        return 0;
}
