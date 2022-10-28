/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "dns-domain.h"
#include "networkd-address-generation.h"
#include "networkd-address.h"
#include "networkd-dhcp-prefix-delegation.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "networkd-radv.h"
#include "networkd-route-util.h"
#include "parse-util.h"
#include "radv-internal.h"
#include "string-util.h"
#include "string-table.h"
#include "strv.h"

void network_adjust_radv(Network *network) {
        assert(network);

        /* After this function is called, network->router_prefix_delegation can be treated as a boolean. */

        if (network->dhcp_pd < 0)
                /* For backward compatibility. */
                network->dhcp_pd = FLAGS_SET(network->router_prefix_delegation, RADV_PREFIX_DELEGATION_DHCP6);

        if (!FLAGS_SET(network->link_local, ADDRESS_FAMILY_IPV6)) {
                if (network->router_prefix_delegation != RADV_PREFIX_DELEGATION_NONE)
                        log_warning("%s: IPv6PrefixDelegation= is enabled but IPv6 link-local addressing is disabled. "
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

bool link_radv_enabled(Link *link) {
        assert(link);

        if (!link_may_have_ipv6ll(link, /* check_multicast = */ true))
                return false;

        if (link->hw_addr.length != ETH_ALEN)
                return false;

        return link->network->router_prefix_delegation;
}

Prefix *prefix_free(Prefix *prefix) {
        if (!prefix)
                return NULL;

        if (prefix->network) {
                assert(prefix->section);
                hashmap_remove(prefix->network->prefixes_by_section, prefix->section);
        }

        config_section_free(prefix->section);
        set_free(prefix->tokens);

        return mfree(prefix);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(Prefix, prefix_free);

static int prefix_new_static(Network *network, const char *filename, unsigned section_line, Prefix **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(prefix_freep) Prefix *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        prefix = hashmap_get(network->prefixes_by_section, n);
        if (prefix) {
                *ret = TAKE_PTR(prefix);
                return 0;
        }

        prefix = new(Prefix, 1);
        if (!prefix)
                return -ENOMEM;

        *prefix = (Prefix) {
                .network = network,
                .section = TAKE_PTR(n),

                .preferred_lifetime = RADV_DEFAULT_PREFERRED_LIFETIME_USEC,
                .valid_lifetime = RADV_DEFAULT_VALID_LIFETIME_USEC,
                .onlink = true,
                .address_auto_configuration = true,
        };

        r = hashmap_ensure_put(&network->prefixes_by_section, &config_section_hash_ops, prefix->section, prefix);
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

        config_section_free(prefix->section);

        return mfree(prefix);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(RoutePrefix, route_prefix_free);

static int route_prefix_new_static(Network *network, const char *filename, unsigned section_line, RoutePrefix **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(route_prefix_freep) RoutePrefix *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        prefix = hashmap_get(network->route_prefixes_by_section, n);
        if (prefix) {
                *ret = TAKE_PTR(prefix);
                return 0;
        }

        prefix = new(RoutePrefix, 1);
        if (!prefix)
                return -ENOMEM;

        *prefix = (RoutePrefix) {
                .network = network,
                .section = TAKE_PTR(n),

                .lifetime = RADV_DEFAULT_VALID_LIFETIME_USEC,
        };

        r = hashmap_ensure_put(&network->route_prefixes_by_section, &config_section_hash_ops, prefix->section, prefix);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(prefix);
        return 0;
}

int link_request_radv_addresses(Link *link) {
        Prefix *p;
        int r;

        assert(link);

        if (!link_radv_enabled(link))
                return 0;

        HASHMAP_FOREACH(p, link->network->prefixes_by_section) {
                _cleanup_set_free_ Set *addresses = NULL;
                struct in6_addr *a;

                if (!p->assign)
                        continue;

                /* radv_generate_addresses() below requires the prefix length <= 64. */
                if (p->prefixlen > 64)
                        continue;

                r = radv_generate_addresses(link, p->tokens, &p->prefix, p->prefixlen, &addresses);
                if (r < 0)
                        return r;

                SET_FOREACH(a, addresses) {
                        _cleanup_(address_freep) Address *address = NULL;

                        r = address_new(&address);
                        if (r < 0)
                                return -ENOMEM;

                        address->source = NETWORK_CONFIG_SOURCE_STATIC;
                        address->family = AF_INET6;
                        address->in_addr.in6 = *a;
                        address->prefixlen = p->prefixlen;
                        address->route_metric = p->route_metric;

                        r = link_request_static_address(link, TAKE_PTR(address), true);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static uint32_t usec_to_lifetime(usec_t usec) {
        uint64_t t;

        if (usec == USEC_INFINITY)
                return UINT32_MAX;

        t = DIV_ROUND_UP(usec, USEC_PER_SEC);
        if (t >= UINT32_MAX)
                return UINT32_MAX;

        return (uint32_t) t;
}

static int radv_set_prefix(Link *link, Prefix *prefix) {
        _cleanup_(sd_radv_prefix_unrefp) sd_radv_prefix *p = NULL;
        int r;

        assert(link);
        assert(link->radv);
        assert(prefix);

        r = sd_radv_prefix_new(&p);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_prefix(p, &prefix->prefix, prefix->prefixlen);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_preferred_lifetime(p, prefix->preferred_lifetime, USEC_INFINITY);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_valid_lifetime(p, prefix->valid_lifetime, USEC_INFINITY);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_onlink(p, prefix->onlink);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_address_autoconfiguration(p, prefix->address_auto_configuration);
        if (r < 0)
                return r;

        return sd_radv_add_prefix(link->radv, p);
}

static int radv_set_route_prefix(Link *link, RoutePrefix *prefix) {
        _cleanup_(sd_radv_route_prefix_unrefp) sd_radv_route_prefix *p = NULL;
        int r;

        assert(link);
        assert(link->radv);
        assert(prefix);

        r = sd_radv_route_prefix_new(&p);
        if (r < 0)
                return r;

        r = sd_radv_route_prefix_set_prefix(p, &prefix->prefix, prefix->prefixlen);
        if (r < 0)
                return r;

        r = sd_radv_route_prefix_set_lifetime(p, prefix->lifetime, USEC_INFINITY);
        if (r < 0)
                return r;

        return sd_radv_add_route_prefix(link->radv, p);
}

static int network_get_ipv6_dns(Network *network, struct in6_addr **ret_addresses, size_t *ret_size) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        size_t n_addresses = 0;

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

                if (!GREEDY_REALLOC(addresses, n_addresses + 1))
                        return -ENOMEM;

                addresses[n_addresses++] = addr->in6;
        }

        *ret_addresses = TAKE_PTR(addresses);
        *ret_size = n_addresses;

        return n_addresses;
}

static int radv_set_dns(Link *link, Link *uplink) {
        _cleanup_free_ struct in6_addr *dns = NULL;
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

                goto set_dns;
        }

        r = network_get_ipv6_dns(link->network, &dns, &n_dns);
        if (r > 0)
                goto set_dns;

        if (uplink) {
                assert(uplink->network);

                r = network_get_ipv6_dns(uplink->network, &dns, &n_dns);
                if (r > 0)
                        goto set_dns;
        }

        return 0;

set_dns:
        return sd_radv_set_rdnss(link->radv,
                                 usec_to_lifetime(link->network->router_dns_lifetime_usec),
                                 dns, n_dns);
}

static int radv_set_domains(Link *link, Link *uplink) {
        _cleanup_free_ char **s = NULL; /* just free() because the strings are owned by the set */
        OrderedSet *search_domains;

        if (!link->network->router_emit_domains)
                return 0;

        search_domains = link->network->router_search_domains;

        if (search_domains)
                goto set_domains;

        search_domains = link->network->search_domains;
        if (search_domains)
                goto set_domains;

        if (uplink) {
                assert(uplink->network);

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
                                 usec_to_lifetime(link->network->router_dns_lifetime_usec),
                                 s);

}

static int radv_find_uplink(Link *link, Link **ret) {
        int r;

        assert(link);

        if (link->network->router_uplink_name)
                return link_get_by_name(link->manager, link->network->router_uplink_name, ret);

        if (link->network->router_uplink_index > 0)
                return link_get_by_index(link->manager, link->network->router_uplink_index, ret);

        if (link->network->router_uplink_index == UPLINK_INDEX_AUTO) {
                if (link_dhcp_pd_is_enabled(link))
                        r = dhcp_pd_find_uplink(link, ret); /* When DHCP-PD is enabled, use its uplink. */
                else
                        r = manager_find_uplink(link->manager, AF_INET6, link, ret);
                if (r < 0)
                        /* It is not necessary to propagate error in automatic selection. */
                        *ret = NULL;
                return 0;
        }

        *ret = NULL;
        return 0;
}

static int radv_configure(Link *link) {
        Link *uplink = NULL;
        RoutePrefix *q;
        Prefix *p;
        int r;

        assert(link);
        assert(link->network);

        if (link->radv)
                return -EBUSY;

        r = sd_radv_new(&link->radv);
        if (r < 0)
                return r;

        r = sd_radv_attach_event(link->radv, link->manager->event, 0);
        if (r < 0)
                return r;

        if (link->hw_addr.length == ETH_ALEN) {
                r = sd_radv_set_mac(link->radv, &link->hw_addr.ether);
                if (r < 0)
                        return r;
        }

        r = sd_radv_set_ifindex(link->radv, link->ifindex);
        if (r < 0)
                return r;

        r = sd_radv_set_managed_information(link->radv, link->network->router_managed);
        if (r < 0)
                return r;

        r = sd_radv_set_other_information(link->radv, link->network->router_other_information);
        if (r < 0)
                return r;

        r = sd_radv_set_router_lifetime(link->radv, link->network->router_lifetime_usec);
        if (r < 0)
                return r;

        if (link->network->router_lifetime_usec > 0) {
                r = sd_radv_set_preference(link->radv, link->network->router_preference);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(p, link->network->prefixes_by_section) {
                r = radv_set_prefix(link, p);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        HASHMAP_FOREACH(q, link->network->route_prefixes_by_section) {
                r = radv_set_route_prefix(link, q);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        (void) radv_find_uplink(link, &uplink);

        r = radv_set_dns(link, uplink);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not set RA DNS: %m");

        r = radv_set_domains(link, uplink);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not set RA Domains: %m");

        return 0;
}

int radv_update_mac(Link *link) {
        bool restart;
        int r;

        assert(link);

        if (!link->radv)
                return 0;

        if (link->hw_addr.length != ETH_ALEN)
                return 0;

        restart = sd_radv_is_running(link->radv);

        r = sd_radv_stop(link->radv);
        if (r < 0)
                return r;

        r = sd_radv_set_mac(link->radv, &link->hw_addr.ether);
        if (r < 0)
                return r;

        if (restart) {
                r = sd_radv_start(link->radv);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int radv_is_ready_to_configure(Link *link) {
        bool needs_uplink = false;
        int r;

        assert(link);
        assert(link->network);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged = */ false))
                return false;

        if (in6_addr_is_null(&link->ipv6ll_address))
                return false;

        if (link->hw_addr.length != ETH_ALEN || hw_addr_is_null(&link->hw_addr))
                return false;

        if (link->network->router_emit_dns && !link->network->router_dns) {
                _cleanup_free_ struct in6_addr *dns = NULL;
                size_t n_dns;

                r = network_get_ipv6_dns(link->network, &dns, &n_dns);
                if (r < 0)
                        return r;

                needs_uplink = r == 0;
        }

        if (link->network->router_emit_domains &&
            !link->network->router_search_domains &&
            !link->network->search_domains)
                needs_uplink = true;

        if (needs_uplink) {
                Link *uplink = NULL;

                if (radv_find_uplink(link, &uplink) < 0)
                        return false;

                if (uplink && !uplink->network)
                        return false;
        }

        return true;
}

static int radv_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        r = radv_is_ready_to_configure(link);
        if (r <= 0)
                return r;

        r = radv_configure(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure IPv6 Router Advertisement engine: %m");

        if (link_has_carrier(link)) {
                r = radv_start(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to start IPv6 Router Advertisement engine: %m");
        }

        log_link_debug(link, "IPv6 Router Advertisement engine is configured%s.",
                       link_has_carrier(link) ? " and started" : "");
        return 1;
}

int link_request_radv(Link *link) {
        int r;

        assert(link);

        if (!link_radv_enabled(link))
                return 0;

        if (link->radv)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_RADV, radv_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the IPv6 Router Advertisement engine: %m");

        log_link_debug(link, "Requested configuring of the IPv6 Router Advertisement engine.");
        return 0;
}

int radv_start(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        if (!link->radv)
                return 0;

        if (!link_has_carrier(link))
                return 0;

        if (in6_addr_is_null(&link->ipv6ll_address))
                return 0;

        if (sd_radv_is_running(link->radv))
                return 0;

        if (link->network->dhcp_pd_announce) {
                r = dhcp_request_prefix_delegation(link);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to request DHCP delegated subnet prefix: %m");
        }

        log_link_debug(link, "Starting IPv6 Router Advertisements");
        return sd_radv_start(link->radv);
}

int radv_add_prefix(
                Link *link,
                const struct in6_addr *prefix,
                uint8_t prefix_len,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

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

        r = sd_radv_prefix_set_preferred_lifetime(p, RADV_DEFAULT_PREFERRED_LIFETIME_USEC, lifetime_preferred_usec);
        if (r < 0)
                return r;

        r = sd_radv_prefix_set_valid_lifetime(p, RADV_DEFAULT_VALID_LIFETIME_USEC, lifetime_valid_usec);
        if (r < 0)
                return r;

        r = sd_radv_add_prefix(link->radv, p);
        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int prefix_section_verify(Prefix *p) {
        assert(p);

        if (section_is_invalid(p->section))
                return -EINVAL;

        if (in6_addr_is_null(&p->prefix))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [IPv6Prefix] section without Prefix= field configured, "
                                         "or specified prefix is the null address. "
                                         "Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename, p->section->line);

        if (p->prefixlen < 3 || p->prefixlen > 128)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Invalid prefix length %u is specified in [IPv6Prefix] section. "
                                         "Valid range is 3…128. Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename, p->prefixlen, p->section->line);

        if (p->prefixlen > 64) {
                log_info("%s:%u: Unusual prefix length %u (> 64) is specified in [IPv6Prefix] section from line %s%s.",
                         p->section->filename, p->section->line,
                         p->prefixlen,
                         p->assign ? ", refusing to assign an address in " : "",
                         p->assign ? IN6_ADDR_PREFIX_TO_STRING(&p->prefix, p->prefixlen) : "");

                p->assign = false;
        }

        if (p->valid_lifetime == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: The valid lifetime of prefix cannot be zero. "
                                         "Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename, p->section->line);

        if (p->preferred_lifetime > p->valid_lifetime)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: The preferred lifetime %s is longer than the valid lifetime %s. "
                                         "Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename,
                                         FORMAT_TIMESPAN(p->preferred_lifetime, USEC_PER_SEC),
                                         FORMAT_TIMESPAN(p->valid_lifetime, USEC_PER_SEC),
                                         p->section->line);

        return 0;
}

void network_drop_invalid_prefixes(Network *network) {
        Prefix *p;

        assert(network);

        HASHMAP_FOREACH(p, network->prefixes_by_section)
                if (prefix_section_verify(p) < 0)
                        prefix_free(p);
}

static int route_prefix_section_verify(RoutePrefix *p) {
        if (section_is_invalid(p->section))
                return -EINVAL;

        if (p->prefixlen > 128)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Invalid prefix length %u is specified in [IPv6RoutePrefix] section. "
                                         "Valid range is 0…128. Ignoring [IPv6RoutePrefix] section from line %u.",
                                         p->section->filename, p->prefixlen, p->section->line);

        if (p->lifetime == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: The lifetime of route cannot be zero. "
                                         "Ignoring [IPv6RoutePrefix] section from line %u.",
                                         p->section->filename, p->section->line);

        return 0;
}

void network_drop_invalid_route_prefixes(Network *network) {
        RoutePrefix *p;

        assert(network);

        HASHMAP_FOREACH(p, network->route_prefixes_by_section)
                if (route_prefix_section_verify(p) < 0)
                        route_prefix_free(p);
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

        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        union in_addr_union a;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &p->prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        (void) in6_addr_mask(&a.in6, p->prefixlen);
        p->prefix = a.in6;

        TAKE_PTR(p);
        return 0;
}

int config_parse_prefix_boolean(
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

        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "OnLink"))
                p->onlink = r;
        else if (streq(lvalue, "AddressAutoconfiguration"))
                p->address_auto_configuration = r;
        else if (streq(lvalue, "Assign"))
                p->assign = r;
        else
                assert_not_reached();

        TAKE_PTR(p);
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

        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (usec != USEC_INFINITY && DIV_ROUND_UP(usec, USEC_PER_SEC) >= UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Lifetime is too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (streq(lvalue, "PreferredLifetimeSec"))
                p->preferred_lifetime = usec;
        else if (streq(lvalue, "ValidLifetimeSec"))
                p->valid_lifetime = usec;
        else
                assert_not_reached();

        TAKE_PTR(p);
        return 0;
}

int config_parse_prefix_metric(
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

        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = safe_atou32(rvalue, &p->route_metric);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(p);
        return 0;
}

int config_parse_prefix_token(
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

        _cleanup_(prefix_free_or_set_invalidp) Prefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = config_parse_address_generation_type(unit, filename, line, section, section_line,
                                                 lvalue, ltype, rvalue, &p->tokens, userdata);
        if (r < 0)
                return r;

        TAKE_PTR(p);
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

        _cleanup_(route_prefix_free_or_set_invalidp) RoutePrefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        union in_addr_union a;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = route_prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &p->prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Route prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        (void) in6_addr_mask(&a.in6, p->prefixlen);
        p->prefix = a.in6;

        TAKE_PTR(p);
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

        _cleanup_(route_prefix_free_or_set_invalidp) RoutePrefix *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = route_prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Route lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (usec != USEC_INFINITY && DIV_ROUND_UP(usec, USEC_PER_SEC) >= UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Lifetime is too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        p->lifetime = usec;

        TAKE_PTR(p);
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

        RADVPrefixDelegation val, *ra = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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

int config_parse_router_lifetime(
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

        usec_t usec, *lifetime = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *lifetime = RADV_DEFAULT_ROUTER_LIFETIME_USEC;
                return 0;
        }

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse router lifetime, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (usec > 0) {
                if (usec < RADV_MIN_ROUTER_LIFETIME_USEC) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Router lifetime %s is too short, using %s.",
                                   FORMAT_TIMESPAN(usec, USEC_PER_SEC),
                                   FORMAT_TIMESPAN(RADV_MIN_ROUTER_LIFETIME_USEC, USEC_PER_SEC));
                        usec = RADV_MIN_ROUTER_LIFETIME_USEC;
                } else if (usec > RADV_MAX_ROUTER_LIFETIME_USEC) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Router lifetime %s is too large, using %s.",
                                   FORMAT_TIMESPAN(usec, USEC_PER_SEC),
                                   FORMAT_TIMESPAN(RADV_MAX_ROUTER_LIFETIME_USEC, USEC_PER_SEC));
                        usec = RADV_MAX_ROUTER_LIFETIME_USEC;
                }
        }

        *lifetime = usec;
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
