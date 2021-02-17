/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "dns-domain.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-radv.h"
#include "parse-util.h"
#include "string-util.h"
#include "string-table.h"
#include "strv.h"

Prefix *prefix_free(Prefix *prefix) {
        if (!prefix)
                return NULL;

        if (prefix->network) {
                assert(prefix->section);
                hashmap_remove(prefix->network->prefixes_by_section, prefix->section);
        }

        network_config_section_free(prefix->section);
        sd_radv_prefix_unref(prefix->radv_prefix);

        return mfree(prefix);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(Prefix, prefix_free);

static int prefix_new(Prefix **ret) {
        _cleanup_(prefix_freep) Prefix *prefix = NULL;

        prefix = new0(Prefix, 1);
        if (!prefix)
                return -ENOMEM;

        if (sd_radv_prefix_new(&prefix->radv_prefix) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(prefix);

        return 0;
}

static int prefix_new_static(Network *network, const char *filename, unsigned section_line, Prefix **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(prefix_freep) Prefix *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        prefix = hashmap_get(network->prefixes_by_section, n);
        if (prefix) {
                *ret = TAKE_PTR(prefix);
                return 0;
        }

        r = prefix_new(&prefix);
        if (r < 0)
                return r;

        prefix->network = network;
        prefix->section = TAKE_PTR(n);

        r = hashmap_ensure_put(&network->prefixes_by_section, &network_config_hash_ops, prefix->section, prefix);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(prefix);

        return 0;
}

RoutePrefix *route_prefix_free(RoutePrefix *prefix) {
        if (!prefix)
                return NULL;

        if (prefix->network) {
                assert(prefix->section);
                hashmap_remove(prefix->network->route_prefixes_by_section, prefix->section);
        }

        network_config_section_free(prefix->section);
        sd_radv_route_prefix_unref(prefix->radv_route_prefix);

        return mfree(prefix);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(RoutePrefix, route_prefix_free);

static int route_prefix_new(RoutePrefix **ret) {
        _cleanup_(route_prefix_freep) RoutePrefix *prefix = NULL;

        prefix = new0(RoutePrefix, 1);
        if (!prefix)
                return -ENOMEM;

        if (sd_radv_route_prefix_new(&prefix->radv_route_prefix) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(prefix);

        return 0;
}

static int route_prefix_new_static(Network *network, const char *filename, unsigned section_line, RoutePrefix **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(route_prefix_freep) RoutePrefix *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        prefix = hashmap_get(network->route_prefixes_by_section, n);
        if (prefix) {
                *ret = TAKE_PTR(prefix);
                return 0;
        }

        r = route_prefix_new(&prefix);
        if (r < 0)
                return r;

        prefix->network = network;
        prefix->section = TAKE_PTR(n);

        r = hashmap_ensure_put(&network->route_prefixes_by_section, &network_config_hash_ops, prefix->section, prefix);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(prefix);

        return 0;
}

void network_drop_invalid_prefixes(Network *network) {
        Prefix *prefix;

        assert(network);

        HASHMAP_FOREACH(prefix, network->prefixes_by_section)
                if (section_is_invalid(prefix->section))
                        prefix_free(prefix);
}

void network_drop_invalid_route_prefixes(Network *network) {
        RoutePrefix *prefix;

        assert(network);

        HASHMAP_FOREACH(prefix, network->route_prefixes_by_section)
                if (section_is_invalid(prefix->section))
                        route_prefix_free(prefix);
}

void network_adjust_radv(Network *network) {
        assert(network);

        /* After this function is called, network->router_prefix_delegation can be treated as a boolean. */

        if (network->dhcp6_pd < 0)
                /* For backward compatibility. */
                network->dhcp6_pd = FLAGS_SET(network->router_prefix_delegation, RADV_PREFIX_DELEGATION_DHCP6);

        if (!FLAGS_SET(network->link_local, ADDRESS_FAMILY_IPV6)) {
                if (network->router_prefix_delegation != RADV_PREFIX_DELEGATION_NONE)
                        log_warning("%s: IPv6PrefixDelegation= is enabled but IPv6 link local addressing is disabled. "
                                    "Disabling IPv6PrefixDelegation=.", network->filename);

                network->router_prefix_delegation = RADV_PREFIX_DELEGATION_NONE;
        }

        if (network->router_prefix_delegation == RADV_PREFIX_DELEGATION_NONE) {
                network->n_router_dns = 0;
                network->router_dns = mfree(network->router_dns);
                network->router_search_domains = ordered_set_free(network->router_search_domains);
        }

        if (!FLAGS_SET(network->router_prefix_delegation, RADV_PREFIX_DELEGATION_STATIC)) {
                network->prefixes_by_section = hashmap_free_with_destructor(network->prefixes_by_section, prefix_free);
                network->route_prefixes_by_section = hashmap_free_with_destructor(network->route_prefixes_by_section, route_prefix_free);
        }
}

int config_parse_prefix(
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
                return log_oom();

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &in6addr, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = sd_radv_prefix_set_prefix(p->radv_prefix, &in6addr.in6, prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to set radv prefix, ignoring assignment: %s", rvalue);
                return 0;
        }

        p = NULL;

        return 0;
}

int config_parse_prefix_flags(
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "OnLink"))
                r = sd_radv_prefix_set_onlink(p->radv_prefix, r);
        else if (streq(lvalue, "AddressAutoconfiguration"))
                r = sd_radv_prefix_set_address_autoconfiguration(p->radv_prefix, r);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to set %s=, ignoring assignment: %m", lvalue);
                return 0;
        }

        p = NULL;

        return 0;
}

int config_parse_prefix_lifetime(
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
                return log_oom();

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        /* a value of 0xffffffff represents infinity */
        if (streq(lvalue, "PreferredLifetimeSec"))
                r = sd_radv_prefix_set_preferred_lifetime(p->radv_prefix,
                                                          DIV_ROUND_UP(usec, USEC_PER_SEC));
        else if (streq(lvalue, "ValidLifetimeSec"))
                r = sd_radv_prefix_set_valid_lifetime(p->radv_prefix,
                                                      DIV_ROUND_UP(usec, USEC_PER_SEC));
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to set %s=, ignoring assignment: %m", lvalue);
                return 0;
        }

        p = NULL;

        return 0;
}

int config_parse_prefix_assign(
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
        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        p->assign = r;
        p = NULL;

        return 0;
}

int config_parse_route_prefix(
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
        _cleanup_(route_prefix_free_or_set_invalidp) RoutePrefix *p = NULL;
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
                return log_oom();

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &in6addr, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Route prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = sd_radv_prefix_set_route_prefix(p->radv_route_prefix, &in6addr.in6, prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to set route prefix, ignoring assignment: %m");
                return 0;
        }

        p = NULL;

        return 0;
}

int config_parse_route_prefix_lifetime(
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
        _cleanup_(route_prefix_free_or_set_invalidp) RoutePrefix *p = NULL;
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = route_prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Route lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        /* a value of 0xffffffff represents infinity */
        r = sd_radv_route_prefix_set_lifetime(p->radv_route_prefix, DIV_ROUND_UP(usec, USEC_PER_SEC));
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to set route lifetime, ignoring assignment: %m");
                return 0;
        }

        p = NULL;

        return 0;
}

static int network_get_ipv6_dns(Network *network, struct in6_addr **ret_addresses, size_t *ret_size) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        size_t n_addresses = 0, n_allocated = 0;

        assert(network);
        assert(ret_addresses);
        assert(ret_size);

        for (size_t i = 0; i < network->n_dns; i++) {
                union in_addr_union *addr;

                if (network->dns[i]->family != AF_INET6)
                        continue;

                addr = &network->dns[i]->address;

                if (in_addr_is_null(AF_INET6, addr) ||
                    in_addr_is_link_local(AF_INET6, addr) ||
                    in_addr_is_localhost(AF_INET6, addr))
                        continue;

                if (!GREEDY_REALLOC(addresses, n_allocated, n_addresses + 1))
                        return -ENOMEM;

                addresses[n_addresses++] = addr->in6;
        }

        *ret_addresses = TAKE_PTR(addresses);
        *ret_size = n_addresses;

        return n_addresses;
}

static int radv_set_dns(Link *link, Link *uplink) {
        _cleanup_free_ struct in6_addr *dns = NULL;
        usec_t lifetime_usec;
        size_t n_dns;
        int r;

        if (!link->network->router_emit_dns)
                return 0;

        if (link->network->router_dns) {
                struct in6_addr *p;

                dns = new(struct in6_addr, link->network->n_router_dns);
                if (!dns)
                        return -ENOMEM;

                p = dns;
                for (size_t i = 0; i < link->network->n_router_dns; i++)
                        if (in6_addr_is_null(&link->network->router_dns[i])) {
                                if (in6_addr_is_set(&link->ipv6ll_address))
                                        *(p++) = link->ipv6ll_address;
                        } else
                                *(p++) = link->network->router_dns[i];

                n_dns = p - dns;
                lifetime_usec = link->network->router_dns_lifetime_usec;

                goto set_dns;
        }

        lifetime_usec = SD_RADV_DEFAULT_DNS_LIFETIME_USEC;

        r = network_get_ipv6_dns(link->network, &dns, &n_dns);
        if (r > 0)
                goto set_dns;

        if (uplink) {
                if (!uplink->network) {
                        log_link_debug(uplink, "Cannot fetch DNS servers as uplink interface is not managed by us");
                        return 0;
                }

                r = network_get_ipv6_dns(uplink->network, &dns, &n_dns);
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

static bool link_radv_enabled(Link *link) {
        assert(link);

        if (!link_ipv6ll_enabled(link))
                return false;

        return link->network->router_prefix_delegation;
}

int radv_configure(Link *link) {
        uint16_t router_lifetime;
        RoutePrefix *q;
        Prefix *p;
        int r;

        assert(link);
        assert(link->network);

        if (!link_radv_enabled(link))
                return 0;

        r = sd_radv_new(&link->radv);
        if (r < 0)
                return r;

        r = sd_radv_attach_event(link->radv, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_radv_set_mac(link->radv, &link->hw_addr.addr.ether);
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

        /* a value of UINT16_MAX represents infinity, 0x0 means this host is not a router */
        if (link->network->router_lifetime_usec == USEC_INFINITY)
                router_lifetime = UINT16_MAX;
        else if (link->network->router_lifetime_usec > (UINT16_MAX - 1) * USEC_PER_SEC)
                router_lifetime = UINT16_MAX - 1;
        else
                router_lifetime = DIV_ROUND_UP(link->network->router_lifetime_usec, USEC_PER_SEC);

        r = sd_radv_set_router_lifetime(link->radv, router_lifetime);
        if (r < 0)
                return r;

        if (router_lifetime > 0) {
                r = sd_radv_set_preference(link->radv, link->network->router_preference);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(p, link->network->prefixes_by_section) {
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

        HASHMAP_FOREACH(q, link->network->route_prefixes_by_section) {
                r = sd_radv_add_route_prefix(link->radv, q->radv_route_prefix, false);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return r;
        }

        return 0;
}

int radv_update_mac(Link *link) {
        bool restart;
        int r;

        assert(link);

        if (!link->radv)
                return 0;

        restart = sd_radv_is_running(link->radv);

        r = sd_radv_stop(link->radv);
        if (r < 0)
                return r;

        r = sd_radv_set_mac(link->radv, &link->hw_addr.addr.ether);
        if (r < 0)
                return r;

        if (restart) {
                r = sd_radv_start(link->radv);
                if (r < 0)
                        return r;
        }

        return 0;
}

int radv_add_prefix(
                Link *link,
                const struct in6_addr *prefix,
                uint8_t prefix_len,
                uint32_t lifetime_preferred,
                uint32_t lifetime_valid) {

        _cleanup_(sd_radv_prefix_unrefp) sd_radv_prefix *p = NULL;
        int r;

        assert(link);

        if (!link->radv)
                return 0;

        r = sd_radv_prefix_new(&p);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_prefix(p, prefix, prefix_len);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_preferred_lifetime(p, lifetime_preferred);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_valid_lifetime(p, lifetime_valid);
        if (r < 0)
                return r;

        r = sd_radv_add_prefix(link->radv, p, true);
        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->n_router_dns = 0;
                n->router_dns = mfree(n->router_dns);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL;
                union in_addr_union a;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                if (streq(w, "_link_local"))
                        a = IN_ADDR_NULL;
                else {
                        r = in_addr_from_string(AF_INET6, w, &a);
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to parse DNS server address, ignoring: %s", w);
                                continue;
                        }

                        if (in_addr_is_null(AF_INET6, &a)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0,
                                           "DNS server address is null, ignoring: %s", w);
                                continue;
                        }
                }

                struct in6_addr *m;
                m = reallocarray(n->router_dns, n->n_router_dns + 1, sizeof(struct in6_addr));
                if (!m)
                        return log_oom();

                m[n->n_router_dns++] = a.in6;
                n->router_dns = m;
        }
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                n->router_search_domains = ordered_set_free(n->router_search_domains);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *w = NULL, *idna = NULL;

                r = extract_first_word(&p, &w, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract word, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = dns_name_apply_idna(w, &idna);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to apply IDNA to domain name '%s', ignoring: %m", w);
                        continue;
                } else if (r == 0)
                        /* transfer ownership to simplify subsequent operations */
                        idna = TAKE_PTR(w);

                r = ordered_set_ensure_allocated(&n->router_search_domains, &string_hash_ops_free);
                if (r < 0)
                        return log_oom();

                r = ordered_set_consume(n->router_search_domains, TAKE_PTR(idna));
                if (r < 0)
                        return log_oom();
        }
}

static const char * const radv_prefix_delegation_table[_RADV_PREFIX_DELEGATION_MAX] = {
        [RADV_PREFIX_DELEGATION_NONE]   = "no",
        [RADV_PREFIX_DELEGATION_STATIC] = "static",
        [RADV_PREFIX_DELEGATION_DHCP6]  = "dhcpv6",
        [RADV_PREFIX_DELEGATION_BOTH]   = "yes",
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

        RADVPrefixDelegation val, *ra = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(lvalue, "IPv6SendRA")) {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid %s= setting, ignoring assignment: %s", lvalue, rvalue);
                        return 0;
                }

                /* When IPv6SendRA= is enabled, only static prefixes are sent by default, and users
                 * need to explicitly enable DHCPv6PrefixDelegation=. */
                *ra = r ? RADV_PREFIX_DELEGATION_STATIC : RADV_PREFIX_DELEGATION_NONE;
                return 0;
        }

        /* For backward compatibility */
        val = radv_prefix_delegation_from_string(rvalue);
        if (val < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, val,
                           "Invalid %s= setting, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        *ra = val;
        return 0;
}

int config_parse_router_preference(
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
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid router preference, ignoring assignment: %s", rvalue);

        return 0;
}
