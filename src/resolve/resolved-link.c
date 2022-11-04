/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if.h>
#include <unistd.h>

#include "sd-network.h"

#include "alloc-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "log-link.h"
#include "mkdir.h"
#include "netif-util.h"
#include "parse-util.h"
#include "resolved-link.h"
#include "resolved-llmnr.h"
#include "resolved-mdns.h"
#include "socket-netlink.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

int link_new(Manager *m, Link **ret, int ifindex) {
        _cleanup_(link_freep) Link *l = NULL;
        int r;

        assert(m);
        assert(ifindex > 0);

        l = new(Link, 1);
        if (!l)
                return -ENOMEM;

        *l = (Link) {
                .ifindex = ifindex,
                .default_route = -1,
                .llmnr_support = RESOLVE_SUPPORT_YES,
                .mdns_support = RESOLVE_SUPPORT_YES,
                .dnssec_mode = _DNSSEC_MODE_INVALID,
                .dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID,
                .operstate = IF_OPER_UNKNOWN,
        };

        if (asprintf(&l->state_file, "/run/systemd/resolve/netif/%i", ifindex) < 0)
                return -ENOMEM;

        r = hashmap_ensure_put(&m->links, NULL, INT_TO_PTR(ifindex), l);
        if (r < 0)
                return r;

        l->manager = m;

        if (ret)
                *ret = l;
        TAKE_PTR(l);

        return 0;
}

void link_flush_settings(Link *l) {
        assert(l);

        l->default_route = -1;
        l->llmnr_support = RESOLVE_SUPPORT_YES;
        l->mdns_support = RESOLVE_SUPPORT_YES;
        l->dnssec_mode = _DNSSEC_MODE_INVALID;
        l->dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID;

        dns_server_unlink_all(l->dns_servers);
        dns_search_domain_unlink_all(l->search_domains);

        l->dnssec_negative_trust_anchors = set_free_free(l->dnssec_negative_trust_anchors);
}

Link *link_free(Link *l) {
        if (!l)
                return NULL;

        /* Send goodbye messages. */
        dns_scope_announce(l->mdns_ipv4_scope, true);
        dns_scope_announce(l->mdns_ipv6_scope, true);

        link_flush_settings(l);

        while (l->addresses)
                (void) link_address_free(l->addresses);

        if (l->manager)
                hashmap_remove(l->manager->links, INT_TO_PTR(l->ifindex));

        dns_scope_free(l->unicast_scope);
        dns_scope_free(l->llmnr_ipv4_scope);
        dns_scope_free(l->llmnr_ipv6_scope);
        dns_scope_free(l->mdns_ipv4_scope);
        dns_scope_free(l->mdns_ipv6_scope);

        free(l->state_file);
        free(l->ifname);

        return mfree(l);
}

void link_allocate_scopes(Link *l) {
        bool unicast_relevant;
        int r;

        assert(l);

        /* If a link that used to be relevant is no longer, or a link that did not use to be relevant now becomes
         * relevant, let's reinit the learnt global DNS server information, since we might talk to different servers
         * now, even if they have the same addresses as before. */

        unicast_relevant = link_relevant(l, AF_UNSPEC, false);
        if (unicast_relevant != l->unicast_relevant) {
                l->unicast_relevant = unicast_relevant;

                dns_server_reset_features_all(l->manager->fallback_dns_servers);
                dns_server_reset_features_all(l->manager->dns_servers);

                /* Also, flush the global unicast scope, to deal with split horizon setups, where talking through one
                 * interface reveals different DNS zones than through others. */
                if (l->manager->unicast_scope)
                        dns_cache_flush(&l->manager->unicast_scope->cache);
        }

        /* And now, allocate all scopes that makes sense now if we didn't have them yet, and drop those which we don't
         * need anymore */

        if (unicast_relevant && l->dns_servers) {
                if (!l->unicast_scope) {
                        dns_server_reset_features_all(l->dns_servers);

                        r = dns_scope_new(l->manager, &l->unicast_scope, l, DNS_PROTOCOL_DNS, AF_UNSPEC);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to allocate DNS scope, ignoring: %m");
                }
        } else
                l->unicast_scope = dns_scope_free(l->unicast_scope);

        if (link_relevant(l, AF_INET, true) &&
            l->llmnr_support != RESOLVE_SUPPORT_NO &&
            l->manager->llmnr_support != RESOLVE_SUPPORT_NO) {
                if (!l->llmnr_ipv4_scope) {
                        r = dns_scope_new(l->manager, &l->llmnr_ipv4_scope, l, DNS_PROTOCOL_LLMNR, AF_INET);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to allocate LLMNR IPv4 scope, ignoring: %m");
                }
        } else
                l->llmnr_ipv4_scope = dns_scope_free(l->llmnr_ipv4_scope);

        if (link_relevant(l, AF_INET6, true) &&
            l->llmnr_support != RESOLVE_SUPPORT_NO &&
            l->manager->llmnr_support != RESOLVE_SUPPORT_NO &&
            socket_ipv6_is_supported()) {
                if (!l->llmnr_ipv6_scope) {
                        r = dns_scope_new(l->manager, &l->llmnr_ipv6_scope, l, DNS_PROTOCOL_LLMNR, AF_INET6);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to allocate LLMNR IPv6 scope, ignoring: %m");
                }
        } else
                l->llmnr_ipv6_scope = dns_scope_free(l->llmnr_ipv6_scope);

        if (link_relevant(l, AF_INET, true) &&
            l->mdns_support != RESOLVE_SUPPORT_NO &&
            l->manager->mdns_support != RESOLVE_SUPPORT_NO) {
                if (!l->mdns_ipv4_scope) {
                        r = dns_scope_new(l->manager, &l->mdns_ipv4_scope, l, DNS_PROTOCOL_MDNS, AF_INET);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to allocate mDNS IPv4 scope, ignoring: %m");
                }
        } else
                l->mdns_ipv4_scope = dns_scope_free(l->mdns_ipv4_scope);

        if (link_relevant(l, AF_INET6, true) &&
            l->mdns_support != RESOLVE_SUPPORT_NO &&
            l->manager->mdns_support != RESOLVE_SUPPORT_NO) {
                if (!l->mdns_ipv6_scope) {
                        r = dns_scope_new(l->manager, &l->mdns_ipv6_scope, l, DNS_PROTOCOL_MDNS, AF_INET6);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to allocate mDNS IPv6 scope, ignoring: %m");
                }
        } else
                l->mdns_ipv6_scope = dns_scope_free(l->mdns_ipv6_scope);
}

void link_add_rrs(Link *l, bool force_remove) {
        int r;

        LIST_FOREACH(addresses, a, l->addresses)
                link_address_add_rrs(a, force_remove);

        if (!force_remove &&
            l->mdns_support == RESOLVE_SUPPORT_YES &&
            l->manager->mdns_support == RESOLVE_SUPPORT_YES) {

                if (l->mdns_ipv4_scope) {
                        r = dns_scope_add_dnssd_services(l->mdns_ipv4_scope);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to add IPv4 DNS-SD services, ignoring: %m");
                }

                if (l->mdns_ipv6_scope) {
                        r = dns_scope_add_dnssd_services(l->mdns_ipv6_scope);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to add IPv6 DNS-SD services, ignoring: %m");
                }

        } else {

                if (l->mdns_ipv4_scope) {
                        r = dns_scope_remove_dnssd_services(l->mdns_ipv4_scope);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to remove IPv4 DNS-SD services, ignoring: %m");
                }

                if (l->mdns_ipv6_scope) {
                        r = dns_scope_remove_dnssd_services(l->mdns_ipv6_scope);
                        if (r < 0)
                                log_link_warning_errno(l, r, "Failed to remove IPv6 DNS-SD services, ignoring: %m");
                }
        }
}

int link_process_rtnl(Link *l, sd_netlink_message *m) {
        const char *n = NULL;
        int r;

        assert(l);
        assert(m);

        r = sd_rtnl_message_link_get_flags(m, &l->flags);
        if (r < 0)
                return r;

        (void) sd_netlink_message_read_u32(m, IFLA_MTU, &l->mtu);
        (void) sd_netlink_message_read_u8(m, IFLA_OPERSTATE, &l->operstate);

        if (sd_netlink_message_read_string(m, IFLA_IFNAME, &n) >= 0 &&
            !streq_ptr(l->ifname, n)) {
                if (l->ifname)
                        log_link_debug(l, "Interface name change detected: %s -> %s", l->ifname, n);

                r = free_and_strdup(&l->ifname, n);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_update_dns_server_one(Link *l, const char *str) {
        _cleanup_free_ char *name = NULL;
        int family, ifindex, r;
        union in_addr_union a;
        DnsServer *s;
        uint16_t port;

        assert(l);
        assert(str);

        r = in_addr_port_ifindex_name_from_string_auto(str, &family, &a, &port, &ifindex, &name);
        if (r < 0)
                return r;

        if (ifindex != 0 && ifindex != l->ifindex)
                return -EINVAL;

        /* By default, the port number is determined with the transaction feature level.
         * See dns_transaction_port() and dns_server_port(). */
        if (IN_SET(port, 53, 853))
                port = 0;

        s = dns_server_find(l->dns_servers, family, &a, port, 0, name);
        if (s) {
                dns_server_move_back_and_unmark(s);
                return 0;
        }

        return dns_server_new(l->manager, NULL, DNS_SERVER_LINK, l, family, &a, port, 0, name);
}

static int link_update_dns_servers(Link *l) {
        _cleanup_strv_free_ char **nameservers = NULL;
        int r;

        assert(l);

        r = sd_network_link_get_dns(l->ifindex, &nameservers);
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
        if (r < 0)
                goto clear;

        dns_server_mark_all(l->dns_servers);

        STRV_FOREACH(nameserver, nameservers) {
                r = link_update_dns_server_one(l, *nameserver);
                if (r < 0)
                        goto clear;
        }

        dns_server_unlink_marked(l->dns_servers);
        return 0;

clear:
        dns_server_unlink_all(l->dns_servers);
        return r;
}

static int link_update_default_route(Link *l) {
        int r;

        assert(l);

        r = sd_network_link_get_dns_default_route(l->ifindex);
        if (r == -ENODATA) {
                r = 0;
                goto clear;
        }
        if (r < 0)
                goto clear;

        l->default_route = r > 0;
        return 0;

clear:
        l->default_route = -1;
        return r;
}

static int link_update_llmnr_support(Link *l) {
        _cleanup_free_ char *b = NULL;
        int r;

        assert(l);

        l->llmnr_support = RESOLVE_SUPPORT_YES; /* yes, yes, we set it twice which is ugly */

        r = sd_network_link_get_llmnr(l->ifindex, &b);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = resolve_support_from_string(b);
        if (r < 0)
                return r;

        l->llmnr_support = r;
        return 0;
}

static int link_update_mdns_support(Link *l) {
        _cleanup_free_ char *b = NULL;
        int r;

        assert(l);

        l->mdns_support = RESOLVE_SUPPORT_YES;

        r = sd_network_link_get_mdns(l->ifindex, &b);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = resolve_support_from_string(b);
        if (r < 0)
                return r;

        l->mdns_support = r;
        return 0;
}

void link_set_dns_over_tls_mode(Link *l, DnsOverTlsMode mode) {

        assert(l);

#if ! ENABLE_DNS_OVER_TLS
        if (mode != DNS_OVER_TLS_NO)
                log_link_warning(l,
                                 "DNS-over-TLS option for the link cannot be enabled or set to opportunistic "
                                 "when systemd-resolved is built without DNS-over-TLS support. "
                                 "Turning off DNS-over-TLS support.");
        return;
#endif

        l->dns_over_tls_mode = mode;
        l->unicast_scope = dns_scope_free(l->unicast_scope);
}

static int link_update_dns_over_tls_mode(Link *l) {
        _cleanup_free_ char *b = NULL;
        int r;

        assert(l);

        l->dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID;

        r = sd_network_link_get_dns_over_tls(l->ifindex, &b);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = dns_over_tls_mode_from_string(b);
        if (r < 0)
                return r;

        l->dns_over_tls_mode = r;
        return 0;
}

void link_set_dnssec_mode(Link *l, DnssecMode mode) {

        assert(l);

#if !HAVE_OPENSSL_OR_GCRYPT
        if (IN_SET(mode, DNSSEC_YES, DNSSEC_ALLOW_DOWNGRADE))
                log_link_warning(l,
                                 "DNSSEC option for the link cannot be enabled or set to allow-downgrade "
                                 "when systemd-resolved is built without a cryptographic library. "
                                 "Turning off DNSSEC support.");
        return;
#endif

        if (l->dnssec_mode == mode)
                return;

        l->dnssec_mode = mode;
        l->unicast_scope = dns_scope_free(l->unicast_scope);
}

static int link_update_dnssec_mode(Link *l) {
        _cleanup_free_ char *m = NULL;
        DnssecMode mode;
        int r;

        assert(l);

        l->dnssec_mode = _DNSSEC_MODE_INVALID;

        r = sd_network_link_get_dnssec(l->ifindex, &m);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        mode = dnssec_mode_from_string(m);
        if (mode < 0)
                return mode;

        link_set_dnssec_mode(l, mode);
        return 0;
}

static int link_update_dnssec_negative_trust_anchors(Link *l) {
        _cleanup_strv_free_ char **ntas = NULL;
        _cleanup_set_free_free_ Set *ns = NULL;
        int r;

        assert(l);

        l->dnssec_negative_trust_anchors = set_free_free(l->dnssec_negative_trust_anchors);

        r = sd_network_link_get_dnssec_negative_trust_anchors(l->ifindex, &ntas);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        ns = set_new(&dns_name_hash_ops);
        if (!ns)
                return -ENOMEM;

        r = set_put_strdupv(&ns, ntas);
        if (r < 0)
                return r;

        l->dnssec_negative_trust_anchors = TAKE_PTR(ns);
        return 0;
}

static int link_update_search_domain_one(Link *l, const char *name, bool route_only) {
        DnsSearchDomain *d;
        int r;

        assert(l);
        assert(name);

        r = dns_search_domain_find(l->search_domains, name, &d);
        if (r < 0)
                return r;
        if (r > 0)
                dns_search_domain_move_back_and_unmark(d);
        else {
                r = dns_search_domain_new(l->manager, &d, DNS_SEARCH_DOMAIN_LINK, l, name);
                if (r < 0)
                        return r;
        }

        d->route_only = route_only;
        return 0;
}

static int link_update_search_domains(Link *l) {
        _cleanup_strv_free_ char **sdomains = NULL, **rdomains = NULL;
        int r, q;

        assert(l);

        r = sd_network_link_get_search_domains(l->ifindex, &sdomains);
        if (r < 0 && r != -ENODATA)
                goto clear;

        q = sd_network_link_get_route_domains(l->ifindex, &rdomains);
        if (q < 0 && q != -ENODATA) {
                r = q;
                goto clear;
        }

        if (r == -ENODATA && q == -ENODATA) {
                /* networkd knows nothing about this interface, and that's fine. */
                r = 0;
                goto clear;
        }

        dns_search_domain_mark_all(l->search_domains);

        STRV_FOREACH(i, sdomains) {
                r = link_update_search_domain_one(l, *i, false);
                if (r < 0)
                        goto clear;
        }

        STRV_FOREACH(i, rdomains) {
                r = link_update_search_domain_one(l, *i, true);
                if (r < 0)
                        goto clear;
        }

        dns_search_domain_unlink_marked(l->search_domains);
        return 0;

clear:
        dns_search_domain_unlink_all(l->search_domains);
        return r;
}

static int link_is_managed(Link *l) {
        _cleanup_free_ char *state = NULL;
        int r;

        assert(l);

        r = sd_network_link_get_setup_state(l->ifindex, &state);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        return !STR_IN_SET(state, "pending", "initialized", "unmanaged");
}

static void link_enter_unmanaged(Link *l) {
        assert(l);

        /* If this link used to be managed, but is now unmanaged, flush all our settings — but only once. */
        if (l->is_managed)
                link_flush_settings(l);

        l->is_managed = false;
}

static void link_read_settings(Link *l) {
        struct stat st;
        int r;

        assert(l);

        /* Read settings from networkd, except when networkd is not managing this interface. */

        r = sd_network_link_get_stat(l->ifindex, &st);
        if (r == -ENOENT)
                return link_enter_unmanaged(l);
        if (r < 0)
                return (void) log_link_warning_errno(l, r, "Failed to stat() networkd's link state file, ignoring: %m");

        if (stat_inode_unmodified(&l->networkd_state_file_stat, &st))
                /* The state file is unmodified. Not necessary to re-read settings. */
                return;

        /* Save the new stat for the next event. */
        l->networkd_state_file_stat = st;

        r = link_is_managed(l);
        if (r < 0)
                return (void) log_link_warning_errno(l, r, "Failed to determine whether the interface is managed, ignoring: %m");
        if (r == 0)
                return link_enter_unmanaged(l);

        l->is_managed = true;

        r = network_link_get_operational_state(l->ifindex, &l->networkd_operstate);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read networkd's link operational state, ignoring: %m");

        r = link_update_dns_servers(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read DNS servers for the interface, ignoring: %m");

        r = link_update_llmnr_support(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read LLMNR support for the interface, ignoring: %m");

        r = link_update_mdns_support(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read mDNS support for the interface, ignoring: %m");

        r = link_update_dns_over_tls_mode(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read DNS-over-TLS mode for the interface, ignoring: %m");

        r = link_update_dnssec_mode(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read DNSSEC mode for the interface, ignoring: %m");

        r = link_update_dnssec_negative_trust_anchors(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read DNSSEC negative trust anchors for the interface, ignoring: %m");

        r = link_update_search_domains(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read search domains for the interface, ignoring: %m");

        r = link_update_default_route(l);
        if (r < 0)
                log_link_warning_errno(l, r, "Failed to read default route setting for the interface, proceeding anyway: %m");
}

int link_update(Link *l) {
        int r;

        assert(l);

        link_read_settings(l);
        r = link_load_user(l);
        if (r < 0)
                return r;

        if (l->llmnr_support != RESOLVE_SUPPORT_NO) {
                r = manager_llmnr_start(l->manager);
                if (r < 0)
                        return r;
        }

        if (l->mdns_support != RESOLVE_SUPPORT_NO) {
                r = manager_mdns_start(l->manager);
                if (r < 0)
                        return r;
        }

        link_allocate_scopes(l);
        link_add_rrs(l, false);

        return 0;
}

bool link_relevant(Link *l, int family, bool local_multicast) {
        assert(l);

        /* A link is relevant for local multicast traffic if it isn't a loopback device, has a link
         * beat, can do multicast and has at least one link-local (or better) IP address.
         *
         * A link is relevant for non-multicast traffic if it isn't a loopback device, has a link beat, and has at
         * least one routable address. */

        if ((l->flags & (IFF_LOOPBACK | IFF_DORMANT)) != 0)
                return false;

        if (!FLAGS_SET(l->flags, IFF_UP | IFF_LOWER_UP))
                return false;

        if (local_multicast &&
            !FLAGS_SET(l->flags, IFF_MULTICAST))
                return false;

        if (!netif_has_carrier(l->operstate, l->flags))
                return false;

        if (l->is_managed &&
            !IN_SET(l->networkd_operstate, LINK_OPERSTATE_DEGRADED_CARRIER, LINK_OPERSTATE_DEGRADED, LINK_OPERSTATE_ROUTABLE))
                return false;

        LIST_FOREACH(addresses, a, l->addresses)
                if ((family == AF_UNSPEC || a->family == family) && link_address_relevant(a, local_multicast))
                        return true;

        return false;
}

LinkAddress *link_find_address(Link *l, int family, const union in_addr_union *in_addr) {
        assert(l);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return NULL;

        if (!in_addr)
                return NULL;

        LIST_FOREACH(addresses, a, l->addresses)
                if (a->family == family && in_addr_equal(family, &a->in_addr, in_addr))
                        return a;

        return NULL;
}

DnsServer* link_set_dns_server(Link *l, DnsServer *s) {
        assert(l);

        if (l->current_dns_server == s)
                return s;

        if (s)
                log_link_debug(l, "Switching to DNS server %s.", strna(dns_server_string_full(s)));

        dns_server_unref(l->current_dns_server);
        l->current_dns_server = dns_server_ref(s);

        if (l->unicast_scope)
                dns_cache_flush(&l->unicast_scope->cache);

        return s;
}

DnsServer *link_get_dns_server(Link *l) {
        assert(l);

        if (!l->current_dns_server)
                link_set_dns_server(l, l->dns_servers);

        return l->current_dns_server;
}

void link_next_dns_server(Link *l, DnsServer *if_current) {
        assert(l);

        /* If the current server of the transaction is specified, and we already are at a different one,
         * don't do anything */
        if (if_current && l->current_dns_server != if_current)
                return;

        /* If currently have no DNS server, then don't do anything, we'll pick it lazily the next time a DNS
         * server is needed. */
        if (!l->current_dns_server)
                return;

        /* Change to the next one, but make sure to follow the linked list only if this server is actually
         * still linked. */
        if (l->current_dns_server->linked && l->current_dns_server->servers_next) {
                link_set_dns_server(l, l->current_dns_server->servers_next);
                return;
        }

        /* Pick the first one again, after we reached the end */
        link_set_dns_server(l, l->dns_servers);
}

DnsOverTlsMode link_get_dns_over_tls_mode(Link *l) {
        assert(l);

        if (l->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                return l->dns_over_tls_mode;

        return manager_get_dns_over_tls_mode(l->manager);
}

DnssecMode link_get_dnssec_mode(Link *l) {
        assert(l);

        if (l->dnssec_mode != _DNSSEC_MODE_INVALID)
                return l->dnssec_mode;

        return manager_get_dnssec_mode(l->manager);
}

bool link_dnssec_supported(Link *l) {
        DnsServer *server;

        assert(l);

        if (link_get_dnssec_mode(l) == DNSSEC_NO)
                return false;

        server = link_get_dns_server(l);
        if (server)
                return dns_server_dnssec_supported(server);

        return true;
}

int link_address_new(Link *l, LinkAddress **ret, int family, const union in_addr_union *in_addr) {
        LinkAddress *a;

        assert(l);
        assert(in_addr);

        a = new(LinkAddress, 1);
        if (!a)
                return -ENOMEM;

        *a = (LinkAddress) {
                .family = family,
                .in_addr = *in_addr,
                .link = l,
                .prefixlen = UCHAR_MAX,
        };

        LIST_PREPEND(addresses, l->addresses, a);
        l->n_addresses++;

        if (ret)
                *ret = a;

        return 0;
}

LinkAddress *link_address_free(LinkAddress *a) {
        if (!a)
                return NULL;

        if (a->link) {
                LIST_REMOVE(addresses, a->link->addresses, a);

                assert(a->link->n_addresses > 0);
                a->link->n_addresses--;

                if (a->llmnr_address_rr) {
                        if (a->family == AF_INET && a->link->llmnr_ipv4_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_address_rr);
                        else if (a->family == AF_INET6 && a->link->llmnr_ipv6_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_address_rr);
                }

                if (a->llmnr_ptr_rr) {
                        if (a->family == AF_INET && a->link->llmnr_ipv4_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_ptr_rr);
                        else if (a->family == AF_INET6 && a->link->llmnr_ipv6_scope)
                                dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_ptr_rr);
                }

                if (a->mdns_address_rr) {
                        if (a->family == AF_INET && a->link->mdns_ipv4_scope)
                                dns_zone_remove_rr(&a->link->mdns_ipv4_scope->zone, a->mdns_address_rr);
                        else if (a->family == AF_INET6 && a->link->mdns_ipv6_scope)
                                dns_zone_remove_rr(&a->link->mdns_ipv6_scope->zone, a->mdns_address_rr);
                }

                if (a->mdns_ptr_rr) {
                        if (a->family == AF_INET && a->link->mdns_ipv4_scope)
                                dns_zone_remove_rr(&a->link->mdns_ipv4_scope->zone, a->mdns_ptr_rr);
                        else if (a->family == AF_INET6 && a->link->mdns_ipv6_scope)
                                dns_zone_remove_rr(&a->link->mdns_ipv6_scope->zone, a->mdns_ptr_rr);
                }
        }

        dns_resource_record_unref(a->llmnr_address_rr);
        dns_resource_record_unref(a->llmnr_ptr_rr);
        dns_resource_record_unref(a->mdns_address_rr);
        dns_resource_record_unref(a->mdns_ptr_rr);

        return mfree(a);
}

void link_address_add_rrs(LinkAddress *a, bool force_remove) {
        int r;

        assert(a);

        if (a->family == AF_INET) {

                if (!force_remove &&
                    link_address_relevant(a, true) &&
                    a->link->llmnr_ipv4_scope &&
                    a->link->llmnr_support == RESOLVE_SUPPORT_YES &&
                    a->link->manager->llmnr_support == RESOLVE_SUPPORT_YES) {

                        if (!a->link->manager->llmnr_host_ipv4_key) {
                                a->link->manager->llmnr_host_ipv4_key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, a->link->manager->llmnr_hostname);
                                if (!a->link->manager->llmnr_host_ipv4_key) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                        }

                        if (!a->llmnr_address_rr) {
                                a->llmnr_address_rr = dns_resource_record_new(a->link->manager->llmnr_host_ipv4_key);
                                if (!a->llmnr_address_rr) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                a->llmnr_address_rr->a.in_addr = a->in_addr.in;
                                a->llmnr_address_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        if (!a->llmnr_ptr_rr) {
                                r = dns_resource_record_new_reverse(&a->llmnr_ptr_rr, a->family, &a->in_addr, a->link->manager->llmnr_hostname);
                                if (r < 0)
                                        goto fail;

                                a->llmnr_ptr_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        r = dns_zone_put(&a->link->llmnr_ipv4_scope->zone, a->link->llmnr_ipv4_scope, a->llmnr_address_rr, true);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add A record to LLMNR zone, ignoring: %m");

                        r = dns_zone_put(&a->link->llmnr_ipv4_scope->zone, a->link->llmnr_ipv4_scope, a->llmnr_ptr_rr, false);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add IPv4 PTR record to LLMNR zone, ignoring: %m");
                } else {
                        if (a->llmnr_address_rr) {
                                if (a->link->llmnr_ipv4_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_address_rr);
                                a->llmnr_address_rr = dns_resource_record_unref(a->llmnr_address_rr);
                        }

                        if (a->llmnr_ptr_rr) {
                                if (a->link->llmnr_ipv4_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv4_scope->zone, a->llmnr_ptr_rr);
                                a->llmnr_ptr_rr = dns_resource_record_unref(a->llmnr_ptr_rr);
                        }
                }

                if (!force_remove &&
                    link_address_relevant(a, true) &&
                    a->link->mdns_ipv4_scope &&
                    a->link->mdns_support == RESOLVE_SUPPORT_YES &&
                    a->link->manager->mdns_support == RESOLVE_SUPPORT_YES) {
                        if (!a->link->manager->mdns_host_ipv4_key) {
                                a->link->manager->mdns_host_ipv4_key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, a->link->manager->mdns_hostname);
                                if (!a->link->manager->mdns_host_ipv4_key) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                        }

                        if (!a->mdns_address_rr) {
                                a->mdns_address_rr = dns_resource_record_new(a->link->manager->mdns_host_ipv4_key);
                                if (!a->mdns_address_rr) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                a->mdns_address_rr->a.in_addr = a->in_addr.in;
                                a->mdns_address_rr->ttl = MDNS_DEFAULT_TTL;
                        }

                        if (!a->mdns_ptr_rr) {
                                r = dns_resource_record_new_reverse(&a->mdns_ptr_rr, a->family, &a->in_addr, a->link->manager->mdns_hostname);
                                if (r < 0)
                                        goto fail;

                                a->mdns_ptr_rr->ttl = MDNS_DEFAULT_TTL;
                        }

                        r = dns_zone_put(&a->link->mdns_ipv4_scope->zone, a->link->mdns_ipv4_scope, a->mdns_address_rr, true);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add A record to MDNS zone, ignoring: %m");

                        r = dns_zone_put(&a->link->mdns_ipv4_scope->zone, a->link->mdns_ipv4_scope, a->mdns_ptr_rr, false);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add IPv4 PTR record to MDNS zone, ignoring: %m");
                } else {
                        if (a->mdns_address_rr) {
                                if (a->link->mdns_ipv4_scope)
                                        dns_zone_remove_rr(&a->link->mdns_ipv4_scope->zone, a->mdns_address_rr);
                                a->mdns_address_rr = dns_resource_record_unref(a->mdns_address_rr);
                        }

                        if (a->mdns_ptr_rr) {
                                if (a->link->mdns_ipv4_scope)
                                        dns_zone_remove_rr(&a->link->mdns_ipv4_scope->zone, a->mdns_ptr_rr);
                                a->mdns_ptr_rr = dns_resource_record_unref(a->mdns_ptr_rr);
                        }
                }
        }

        if (a->family == AF_INET6) {

                if (!force_remove &&
                    link_address_relevant(a, true) &&
                    a->link->llmnr_ipv6_scope &&
                    a->link->llmnr_support == RESOLVE_SUPPORT_YES &&
                    a->link->manager->llmnr_support == RESOLVE_SUPPORT_YES) {

                        if (!a->link->manager->llmnr_host_ipv6_key) {
                                a->link->manager->llmnr_host_ipv6_key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, a->link->manager->llmnr_hostname);
                                if (!a->link->manager->llmnr_host_ipv6_key) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                        }

                        if (!a->llmnr_address_rr) {
                                a->llmnr_address_rr = dns_resource_record_new(a->link->manager->llmnr_host_ipv6_key);
                                if (!a->llmnr_address_rr) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                a->llmnr_address_rr->aaaa.in6_addr = a->in_addr.in6;
                                a->llmnr_address_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        if (!a->llmnr_ptr_rr) {
                                r = dns_resource_record_new_reverse(&a->llmnr_ptr_rr, a->family, &a->in_addr, a->link->manager->llmnr_hostname);
                                if (r < 0)
                                        goto fail;

                                a->llmnr_ptr_rr->ttl = LLMNR_DEFAULT_TTL;
                        }

                        r = dns_zone_put(&a->link->llmnr_ipv6_scope->zone, a->link->llmnr_ipv6_scope, a->llmnr_address_rr, true);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add AAAA record to LLMNR zone, ignoring: %m");

                        r = dns_zone_put(&a->link->llmnr_ipv6_scope->zone, a->link->llmnr_ipv6_scope, a->llmnr_ptr_rr, false);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add IPv6 PTR record to LLMNR zone, ignoring: %m");
                } else {
                        if (a->llmnr_address_rr) {
                                if (a->link->llmnr_ipv6_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_address_rr);
                                a->llmnr_address_rr = dns_resource_record_unref(a->llmnr_address_rr);
                        }

                        if (a->llmnr_ptr_rr) {
                                if (a->link->llmnr_ipv6_scope)
                                        dns_zone_remove_rr(&a->link->llmnr_ipv6_scope->zone, a->llmnr_ptr_rr);
                                a->llmnr_ptr_rr = dns_resource_record_unref(a->llmnr_ptr_rr);
                        }
                }

                if (!force_remove &&
                    link_address_relevant(a, true) &&
                    a->link->mdns_ipv6_scope &&
                    a->link->mdns_support == RESOLVE_SUPPORT_YES &&
                    a->link->manager->mdns_support == RESOLVE_SUPPORT_YES) {

                        if (!a->link->manager->mdns_host_ipv6_key) {
                                a->link->manager->mdns_host_ipv6_key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, a->link->manager->mdns_hostname);
                                if (!a->link->manager->mdns_host_ipv6_key) {
                                        r = -ENOMEM;
                                        goto fail;
                                }
                        }

                        if (!a->mdns_address_rr) {
                                a->mdns_address_rr = dns_resource_record_new(a->link->manager->mdns_host_ipv6_key);
                                if (!a->mdns_address_rr) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                a->mdns_address_rr->aaaa.in6_addr = a->in_addr.in6;
                                a->mdns_address_rr->ttl = MDNS_DEFAULT_TTL;
                        }

                        if (!a->mdns_ptr_rr) {
                                r = dns_resource_record_new_reverse(&a->mdns_ptr_rr, a->family, &a->in_addr, a->link->manager->mdns_hostname);
                                if (r < 0)
                                        goto fail;

                                a->mdns_ptr_rr->ttl = MDNS_DEFAULT_TTL;
                        }

                        r = dns_zone_put(&a->link->mdns_ipv6_scope->zone, a->link->mdns_ipv6_scope, a->mdns_address_rr, true);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add AAAA record to MDNS zone, ignoring: %m");

                        r = dns_zone_put(&a->link->mdns_ipv6_scope->zone, a->link->mdns_ipv6_scope, a->mdns_ptr_rr, false);
                        if (r < 0)
                                log_link_warning_errno(a->link, r, "Failed to add IPv6 PTR record to MDNS zone, ignoring: %m");
                } else {
                        if (a->mdns_address_rr) {
                                if (a->link->mdns_ipv6_scope)
                                        dns_zone_remove_rr(&a->link->mdns_ipv6_scope->zone, a->mdns_address_rr);
                                a->mdns_address_rr = dns_resource_record_unref(a->mdns_address_rr);
                        }

                        if (a->mdns_ptr_rr) {
                                if (a->link->mdns_ipv6_scope)
                                        dns_zone_remove_rr(&a->link->mdns_ipv6_scope->zone, a->mdns_ptr_rr);
                                a->mdns_ptr_rr = dns_resource_record_unref(a->mdns_ptr_rr);
                        }
                }
        }

        return;

fail:
        log_link_debug_errno(a->link, r, "Failed to update address RRs, ignoring: %m");
}

int link_address_update_rtnl(LinkAddress *a, sd_netlink_message *m) {
        int r;

        assert(a);
        assert(m);

        r = sd_rtnl_message_addr_get_flags(m, &a->flags);
        if (r < 0)
                return r;

        (void) sd_rtnl_message_addr_get_prefixlen(m, &a->prefixlen);
        (void) sd_rtnl_message_addr_get_scope(m, &a->scope);

        link_allocate_scopes(a->link);
        link_add_rrs(a->link, false);

        return 0;
}

bool link_address_relevant(LinkAddress *a, bool local_multicast) {
        assert(a);

        if (a->flags & (IFA_F_DEPRECATED|IFA_F_TENTATIVE))
                return false;

        if (a->scope >= (local_multicast ? RT_SCOPE_HOST : RT_SCOPE_LINK))
                return false;

        return true;
}

static bool link_needs_save(Link *l) {
        assert(l);

        /* Returns true if any of the settings where set different from the default */

        if (l->is_managed)
                return false;

        if (l->llmnr_support != RESOLVE_SUPPORT_YES ||
            l->mdns_support != RESOLVE_SUPPORT_YES ||
            l->dnssec_mode != _DNSSEC_MODE_INVALID ||
            l->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                return true;

        if (l->dns_servers ||
            l->search_domains)
                return true;

        if (!set_isempty(l->dnssec_negative_trust_anchors))
                return true;

        if (l->default_route >= 0)
                return true;

        return false;
}

int link_save_user(Link *l) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *v;
        int r;

        assert(l);
        assert(l->state_file);

        if (!link_needs_save(l)) {
                (void) unlink(l->state_file);
                return 0;
        }

        r = mkdir_parents(l->state_file, 0700);
        if (r < 0)
                goto fail;

        r = fopen_temporary(l->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        (void) fchmod(fileno(f), 0644);

        fputs("# This is private data. Do not parse.\n", f);

        v = resolve_support_to_string(l->llmnr_support);
        if (v)
                fprintf(f, "LLMNR=%s\n", v);

        v = resolve_support_to_string(l->mdns_support);
        if (v)
                fprintf(f, "MDNS=%s\n", v);

        v = dnssec_mode_to_string(l->dnssec_mode);
        if (v)
                fprintf(f, "DNSSEC=%s\n", v);

        v = dns_over_tls_mode_to_string(l->dns_over_tls_mode);
        if (v)
                fprintf(f, "DNSOVERTLS=%s\n", v);

        if (l->default_route >= 0)
                fprintf(f, "DEFAULT_ROUTE=%s\n", yes_no(l->default_route));

        if (l->dns_servers) {
                fputs("SERVERS=", f);
                LIST_FOREACH(servers, server, l->dns_servers) {

                        if (server != l->dns_servers)
                                fputc(' ', f);

                        v = dns_server_string_full(server);
                        if (!v) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        fputs(v, f);
                }
                fputc('\n', f);
        }

        if (l->search_domains) {
                fputs("DOMAINS=", f);
                LIST_FOREACH(domains, domain, l->search_domains) {

                        if (domain != l->search_domains)
                                fputc(' ', f);

                        if (domain->route_only)
                                fputc('~', f);

                        fputs(DNS_SEARCH_DOMAIN_NAME(domain), f);
                }
                fputc('\n', f);
        }

        if (!set_isempty(l->dnssec_negative_trust_anchors)) {
                bool space = false;
                char *nta;

                fputs("NTAS=", f);
                SET_FOREACH(nta, l->dnssec_negative_trust_anchors) {

                        if (space)
                                fputc(' ', f);

                        fputs(nta, f);
                        space = true;
                }
                fputc('\n', f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, l->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink(l->state_file);

        if (temp_path)
                (void) unlink(temp_path);

        return log_link_error_errno(l, r, "Failed to save link data %s: %m", l->state_file);
}

int link_load_user(Link *l) {
        _cleanup_free_ char
                *llmnr = NULL,
                *mdns = NULL,
                *dnssec = NULL,
                *dns_over_tls = NULL,
                *servers = NULL,
                *domains = NULL,
                *ntas = NULL,
                *default_route = NULL;

        ResolveSupport s;
        const char *p;
        int r;

        assert(l);
        assert(l->state_file);

        /* Try to load only a single time */
        if (l->loaded)
                return 0;
        l->loaded = true;

        if (l->is_managed)
                return 0; /* if the device is managed, then networkd is our configuration source, not the bus API */

        r = parse_env_file(NULL, l->state_file,
                           "LLMNR", &llmnr,
                           "MDNS", &mdns,
                           "DNSSEC", &dnssec,
                           "DNSOVERTLS", &dns_over_tls,
                           "SERVERS", &servers,
                           "DOMAINS", &domains,
                           "NTAS", &ntas,
                           "DEFAULT_ROUTE", &default_route);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                goto fail;

        link_flush_settings(l);

        /* If we can't recognize the LLMNR or MDNS setting we don't override the default */
        s = resolve_support_from_string(llmnr);
        if (s >= 0)
                l->llmnr_support = s;

        s = resolve_support_from_string(mdns);
        if (s >= 0)
                l->mdns_support = s;

        r = parse_boolean(default_route);
        if (r >= 0)
                l->default_route = r;

        /* If we can't recognize the DNSSEC setting, then set it to invalid, so that the daemon default is used. */
        l->dnssec_mode = dnssec_mode_from_string(dnssec);

        /* Same for DNSOverTLS */
        l->dns_over_tls_mode = dns_over_tls_mode_from_string(dns_over_tls);

        for (p = servers;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        break;

                r = link_update_dns_server_one(l, word);
                if (r < 0) {
                        log_link_debug_errno(l, r, "Failed to load DNS server '%s', ignoring: %m", word);
                        continue;
                }
        }

        for (p = domains;;) {
                _cleanup_free_ char *word = NULL;
                const char *n;
                bool is_route;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        goto fail;
                if (r == 0)
                        break;

                is_route = word[0] == '~';
                n = is_route ? word + 1 : word;

                r = link_update_search_domain_one(l, n, is_route);
                if (r < 0) {
                        log_link_debug_errno(l, r, "Failed to load search domain '%s', ignoring: %m", word);
                        continue;
                }
        }

        if (ntas) {
                _cleanup_set_free_free_ Set *ns = NULL;

                ns = set_new(&dns_name_hash_ops);
                if (!ns) {
                        r = -ENOMEM;
                        goto fail;
                }

                r = set_put_strsplit(ns, ntas, NULL, 0);
                if (r < 0)
                        goto fail;

                l->dnssec_negative_trust_anchors = TAKE_PTR(ns);
        }

        return 0;

fail:
        return log_link_error_errno(l, r, "Failed to load link data %s: %m", l->state_file);
}

void link_remove_user(Link *l) {
        assert(l);
        assert(l->state_file);

        (void) unlink(l->state_file);
}

bool link_negative_trust_anchor_lookup(Link *l, const char *name) {
        int r;

        assert(l);
        assert(name);

        /* Checks whether the specified domain (or any of its parent domains) are listed as per-link NTA. */

        for (;;) {
                if (set_contains(l->dnssec_negative_trust_anchors, name))
                        return true;

                /* And now, let's look at the parent, and check that too */
                r = dns_name_parent(&name);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
        }

        return false;
}
