/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2017 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "dns-domain.h"
#include "ndisc-router-internal.h"
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

bool link_radv_enabled(Link *link) {
        assert(link);

        if (!link_may_have_ipv6ll(link, /* check_multicast = */ true))
                return false;

        if (link->hw_addr.length != ETH_ALEN)
                return false;

        return link->network->router_prefix_delegation;
}

Prefix* prefix_free(Prefix *prefix) {
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

                .prefix.flags = ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
                .prefix.valid_lifetime = RADV_DEFAULT_VALID_LIFETIME_USEC,
                .prefix.preferred_lifetime = RADV_DEFAULT_PREFERRED_LIFETIME_USEC,
                .prefix.valid_until = USEC_INFINITY,
                .prefix.preferred_until = USEC_INFINITY,
        };

        r = hashmap_ensure_put(&network->prefixes_by_section, &config_section_hash_ops, prefix->section, prefix);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(prefix);
        return 0;
}

RoutePrefix* route_prefix_free(RoutePrefix *prefix) {
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

                .route.lifetime = RADV_DEFAULT_VALID_LIFETIME_USEC,
                .route.valid_until = USEC_INFINITY,
        };

        r = hashmap_ensure_put(&network->route_prefixes_by_section, &config_section_hash_ops, prefix->section, prefix);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(prefix);
        return 0;
}

Prefix64* prefix64_free(Prefix64 *prefix) {
        if (!prefix)
                return NULL;

        if (prefix->network) {
                assert(prefix->section);
                hashmap_remove(prefix->network->pref64_prefixes_by_section, prefix->section);
        }

        config_section_free(prefix->section);

        return mfree(prefix);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(Prefix64, prefix64_free);

static int prefix64_new_static(Network *network, const char *filename, unsigned section_line, Prefix64 **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(prefix64_freep) Prefix64 *prefix = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        prefix = hashmap_get(network->pref64_prefixes_by_section, n);
        if (prefix) {
                *ret = TAKE_PTR(prefix);
                return 0;
        }

        prefix = new(Prefix64, 1);
        if (!prefix)
                return -ENOMEM;

        *prefix = (Prefix64) {
                .network = network,
                .section = TAKE_PTR(n),

                .prefix64.lifetime = RADV_PREF64_DEFAULT_LIFETIME_USEC,
                .prefix64.valid_until = USEC_INFINITY,
        };

        r = hashmap_ensure_put(&network->pref64_prefixes_by_section, &config_section_hash_ops, prefix->section, prefix);
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
                if (!p->assign)
                        continue;

                /* radv_generate_addresses() below requires the prefix length <= 64. */
                if (p->prefix.prefixlen > 64)
                        continue;

                _cleanup_hashmap_free_ Hashmap *tokens_by_address = NULL;
                r = radv_generate_addresses(link, p->tokens, &p->prefix.address, p->prefix.prefixlen, &tokens_by_address);
                if (r < 0)
                        return r;

                IPv6Token *token;
                struct in6_addr *a;
                HASHMAP_FOREACH_KEY(token, a, tokens_by_address) {
                        _cleanup_(address_unrefp) Address *address = NULL;

                        r = address_new(&address);
                        if (r < 0)
                                return -ENOMEM;

                        address->source = NETWORK_CONFIG_SOURCE_STATIC;
                        address->family = AF_INET6;
                        address->in_addr.in6 = *a;
                        address->prefixlen = p->prefix.prefixlen;
                        address->route_metric = p->route_metric;
                        address->token = ipv6_token_ref(token);

                        r = link_request_static_address(link, address);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int link_reconfigure_radv_address(Address *address, Link *link) {
        int r;

        assert(address);
        assert(address->source == NETWORK_CONFIG_SOURCE_STATIC);
        assert(link);

        r = regenerate_address(address, link);
        if (r <= 0)
                return r;

        r = link_request_static_address(link, address);
        if (r < 0)
                return r;

        if (link->static_address_messages != 0) {
                link->static_addresses_configured = false;
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
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
        return sd_radv_add_rdnss(
                        link->radv,
                        n_dns,
                        dns,
                        link->network->router_dns_lifetime_usec,
                        /* valid_until = */ USEC_INFINITY);
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

        return sd_radv_add_dnssl(
                        link->radv,
                        s,
                        link->network->router_dns_lifetime_usec,
                        /* valid_until = */ USEC_INFINITY);
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

        r = sd_radv_set_hop_limit(link->radv, link->network->router_hop_limit);
        if (r < 0)
                return r;

        r = sd_radv_set_preference(link->radv, link->network->router_preference);
        if (r < 0)
                return r;

        r = sd_radv_set_reachable_time(link->radv, link->network->router_reachable_usec);
        if (r < 0)
                return r;

        r = sd_radv_set_retransmit(link->radv, link->network->router_retransmit_usec);
        if (r < 0)
                return r;

        Prefix *p;
        HASHMAP_FOREACH(p, link->network->prefixes_by_section) {
                r = sd_radv_add_prefix(
                                link->radv,
                                &p->prefix.address,
                                p->prefix.prefixlen,
                                p->prefix.flags,
                                p->prefix.valid_lifetime,
                                p->prefix.preferred_lifetime,
                                p->prefix.valid_until,
                                p->prefix.preferred_until);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        RoutePrefix *q;
        HASHMAP_FOREACH(q, link->network->route_prefixes_by_section) {
                r = sd_radv_add_route(
                                link->radv,
                                &q->route.address,
                                q->route.prefixlen,
                                q->route.preference,
                                q->route.lifetime,
                                q->route.valid_until);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        Prefix64 *n;
        HASHMAP_FOREACH(n, link->network->pref64_prefixes_by_section) {
                r = sd_radv_add_prefix64(
                                link->radv,
                                &n->prefix64.prefix,
                                n->prefix64.prefixlen,
                                n->prefix64.lifetime,
                                n->prefix64.valid_until);
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

        if (link->network->router_home_agent_information) {
                r = sd_radv_set_home_agent(
                                link->radv,
                                link->network->router_home_agent_preference,
                                link->network->home_agent_lifetime_usec,
                                /* valid_until = */ USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        return 0;
}

int radv_update_mac(Link *link) {
        assert(link);

        if (!link->radv)
                return 0;

        if (link->hw_addr.length != ETH_ALEN)
                return 0;

        return sd_radv_set_mac(link->radv, &link->hw_addr.ether);
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

int link_drop_radv_config(Link *link, Network *network) {
        int ret = 0;

        assert(link);
        assert(link->network);

        if (link->network == network)
                return 0; /* .network file is unchanged. It is not necessary to reconfigure the server. */

        // FIXME: check detailed settings and do not stop if nothing changed.
        // FIXME: save dynamic prefixes acquired by DHCP-PD.
        ret = sd_radv_stop(link->radv);
        link->radv = sd_radv_unref(link->radv);
        return ret;
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

        r = sd_radv_set_link_local_address(link->radv, &link->ipv6ll_address);
        if (r < 0)
                return r;

        log_link_debug(link, "Starting IPv6 Router Advertisements");
        return sd_radv_start(link->radv);
}

int radv_add_prefix(
                Link *link,
                const struct in6_addr *prefix,
                uint8_t prefix_len,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        int r;

        assert(link);
        assert(prefix);

        if (!link->radv)
                return 0;

        r = sd_radv_add_prefix(
                        link->radv,
                        prefix,
                        prefix_len,
                        ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO,
                        RADV_DEFAULT_VALID_LIFETIME_USEC,
                        RADV_DEFAULT_PREFERRED_LIFETIME_USEC,
                        lifetime_valid_usec,
                        lifetime_preferred_usec);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        if (sd_radv_is_running(link->radv)) {
                /* Announce updated prefixe now. */
                r = sd_radv_send(link->radv);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int prefix_section_verify(Prefix *p) {
        assert(p);

        if (section_is_invalid(p->section))
                return -EINVAL;

        if (in6_addr_is_null(&p->prefix.address))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [IPv6Prefix] section without Prefix= field configured, "
                                         "or specified prefix is the null address. "
                                         "Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename, p->section->line);

        if (p->prefix.prefixlen < 3 || p->prefix.prefixlen > 128)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Invalid prefix length %u is specified in [IPv6Prefix] section. "
                                         "Valid range is 3…128. Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename, p->prefix.prefixlen, p->section->line);

        if (p->prefix.prefixlen > 64) {
                log_info("%s:%u: Unusual prefix length %u (> 64) is specified in [IPv6Prefix] section from line %s%s.",
                         p->section->filename, p->section->line,
                         p->prefix.prefixlen,
                         p->assign ? ", refusing to assign an address in " : "",
                         p->assign ? IN6_ADDR_PREFIX_TO_STRING(&p->prefix.address, p->prefix.prefixlen) : "");

                p->assign = false;
        }

        if (p->prefix.preferred_lifetime > p->prefix.valid_lifetime)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: The preferred lifetime %s is longer than the valid lifetime %s. "
                                         "Ignoring [IPv6Prefix] section from line %u.",
                                         p->section->filename,
                                         FORMAT_TIMESPAN(p->prefix.preferred_lifetime, USEC_PER_SEC),
                                         FORMAT_TIMESPAN(p->prefix.valid_lifetime, USEC_PER_SEC),
                                         p->section->line);

        return 0;
}

static int route_prefix_section_verify(RoutePrefix *p) {
        if (section_is_invalid(p->section))
                return -EINVAL;

        if (p->route.prefixlen > 128)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Invalid prefix length %u is specified in [IPv6RoutePrefix] section. "
                                         "Valid range is 0…128. Ignoring [IPv6RoutePrefix] section from line %u.",
                                         p->section->filename, p->route.prefixlen, p->section->line);

        return 0;
}

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
                network->pref64_prefixes_by_section = hashmap_free_with_destructor(network->pref64_prefixes_by_section, prefix64_free);
        }

        if (!network->router_prefix_delegation)
                return;

        /* Below, let's verify router settings, if enabled. */

        if (network->router_lifetime_usec == 0 && network->router_preference != SD_NDISC_PREFERENCE_MEDIUM)
                /* RFC 4191, Section 2.2,
                 * If the Router Lifetime is zero, the preference value MUST be set to (00) by the sender.
                 *
                 * Note, radv_send_router() gracefully handle that. So, it is not necessary to refuse, but
                 * let's warn about that. */
                log_notice("%s: RouterPreference=%s specified with RouterLifetimeSec=0, ignoring RouterPreference= setting.",
                           network->filename, ndisc_router_preference_to_string(network->router_preference));

        Prefix *prefix;
        HASHMAP_FOREACH(prefix, network->prefixes_by_section)
                if (prefix_section_verify(prefix) < 0)
                        prefix_free(prefix);

        RoutePrefix *route;
        HASHMAP_FOREACH(route, network->route_prefixes_by_section)
                if (route_prefix_section_verify(route) < 0)
                        route_prefix_free(route);

        Prefix64 *pref64;
        HASHMAP_FOREACH(pref64, network->pref64_prefixes_by_section)
                 if (section_is_invalid(pref64->section))
                         prefix64_free(pref64);
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

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &p->prefix.prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        (void) in6_addr_mask(&a.in6, p->prefix.prefixlen);
        p->prefix.address = a.in6;

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

        if (ltype != 0)
                SET_FLAG(p->prefix.flags, ltype, r);
        else {
                assert(streq(lvalue, "Assign"));
                p->assign = r;
        }

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
                p->prefix.preferred_lifetime = usec;
        else if (streq(lvalue, "ValidLifetimeSec"))
                p->prefix.valid_lifetime = usec;
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

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &p->route.prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Route prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        (void) in6_addr_mask(&a.in6, p->route.prefixlen);
        p->route.address = a.in6;

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

        p->route.lifetime = usec;

        TAKE_PTR(p);
        return 0;
}

int config_parse_route_prefix_preference(
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
        int r;

        assert(filename);

        r = route_prefix_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = config_parse_router_preference(unit, filename, line, section, section_line,
                                           lvalue, ltype, rvalue, &p->route.preference, NULL);
        if (r <= 0)
                return r;

        TAKE_PTR(p);
        return 0;
}

int config_parse_pref64_prefix(
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

        _cleanup_(prefix64_free_or_set_invalidp) Prefix64 *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        union in_addr_union a;
        uint8_t prefixlen;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix64_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "PREF64 prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (!IN_SET(prefixlen, 96, 64, 56, 48, 40, 32)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "PREF64 prefixlen is invalid, ignoring assignment: %s", rvalue);
                return 0;
       }

        (void) in6_addr_mask(&a.in6, prefixlen);
        p->prefix64.prefix = a.in6;
        p->prefix64.prefixlen = prefixlen;

        TAKE_PTR(p);
        return 0;
}

int config_parse_pref64_prefix_lifetime(
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

        _cleanup_(prefix64_free_or_set_invalidp) Prefix64 *p = NULL;
        Network *network = ASSERT_PTR(userdata);
        usec_t usec;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        r = prefix64_new_static(network, filename, section_line, &p);
        if (r < 0)
                return log_oom();

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "PREF64 lifetime is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (usec == USEC_INFINITY || DIV_ROUND_UP(usec, 8 * USEC_PER_SEC) >= UINT64_C(1) << 13) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "PREF64 lifetime is too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        p->prefix64.lifetime = usec;

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

                if (!GREEDY_REALLOC(n->router_dns, n->n_router_dns + 1))
                        return log_oom();

                n->router_dns[n->n_router_dns++] = a.in6;
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
                 * need to explicitly enable DHCPPrefixDelegation=. */
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

int config_parse_router_uint32_msec_usec(
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

        usec_t usec, *router_usec = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *router_usec = 0;
                return 0;
        }

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (usec != USEC_INFINITY &&
            usec > RADV_MAX_UINT32_MSEC_USEC) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid [%s] %s=, ignoring assignment: %s", section, lvalue, rvalue);
                return 0;
        }

        *router_usec = usec;
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

        uint8_t *preference = ASSERT_PTR(data);

        if (isempty(rvalue) || STR_IN_SET(rvalue, "medium", "normal", "default"))
                *preference = SD_NDISC_PREFERENCE_MEDIUM;
        else if (streq(rvalue, "high"))
                *preference = SD_NDISC_PREFERENCE_HIGH;
        else if (streq(rvalue, "low"))
                *preference = SD_NDISC_PREFERENCE_LOW;
        else
                return log_syntax_parse_error(unit, filename, line, 0, lvalue, rvalue);

        return 1;
}

int config_parse_router_home_agent_lifetime(
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

        usec_t usec, *home_agent_lifetime_usec = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *home_agent_lifetime_usec = 0;
                return 0;
        }

        r = parse_sec(rvalue, &usec);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (!timestamp_is_set(usec) ||
            usec > RADV_HOME_AGENT_MAX_LIFETIME_USEC) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid [%s] %s=, ignoring assignment: %s", section, lvalue, rvalue);
                return 0;
        }

        *home_agent_lifetime_usec = usec;
        return 0;
}
