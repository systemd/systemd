/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-dhcp6-lease.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-resolver-internal.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "network-internal.h"
#include "networkd-dhcp-common.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-manager-bus.h"
#include "networkd-network.h"
#include "networkd-ntp.h"
#include "networkd-state-file.h"
#include "networkd-wwan.h"
#include "ordered-set.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

static int ordered_set_put_dns_servers(OrderedSet **s, int ifindex, struct in_addr_full **dns, unsigned n) {
        int r;

        assert(s);
        assert(dns || n == 0);

        FOREACH_ARRAY(a, dns, n) {
                const char *p;

                if ((*a)->ifindex != 0 && (*a)->ifindex != ifindex)
                        return 0;

                p = in_addr_full_to_string(*a);
                if (!p)
                        return 0;

                r = ordered_set_put_strdup(s, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ordered_set_put_in4_addrv(
                OrderedSet **s,
                const struct in_addr *addresses,
                size_t n,
                bool (*predicate)(const struct in_addr *addr)) {

        int r;

        assert(s);
        assert(n == 0 || addresses);

        FOREACH_ARRAY(a, addresses, n) {
                if (predicate && !predicate(a))
                        continue;

                r = ordered_set_put_strdup(s, IN4_ADDR_TO_STRING(a));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int ordered_set_put_in6_addrv(
                OrderedSet **s,
                const struct in6_addr *addresses,
                size_t n) {

        int r;

        assert(s);
        assert(n == 0 || addresses);

        FOREACH_ARRAY(a, addresses, n) {
                r = ordered_set_put_strdup(s, IN6_ADDR_TO_STRING(a));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_put_dns(Link *link, OrderedSet **s) {
        int r;

        assert(link);
        assert(link->network);
        assert(s);

        if (link->n_dns != UINT_MAX)
                return ordered_set_put_dns_servers(s, link->ifindex, link->dns, link->n_dns);

        r = ordered_set_put_dns_servers(s, link->ifindex, link->network->dns, link->network->n_dns);
        if (r < 0)
                return r;

        Bearer *b;

        if (link_get_bearer(link, &b) >= 0) {
                r = ordered_set_put_dns_servers(s, link->ifindex, b->dns, b->n_dns);
                if (r < 0)
                        return r;
        }

        if (link->dhcp_lease && link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP4)) {
                const struct in_addr *addresses;

                r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                if (r >= 0) {
                        r = ordered_set_put_in4_addrv(s, addresses, r, in4_addr_is_non_local);
                        if (r < 0)
                                return r;
                }
        }

        if (link->dhcp_lease && link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP4)) {
                sd_dns_resolver *resolvers;

                r = sd_dhcp_lease_get_dnr(link->dhcp_lease, &resolvers);
                if (r >= 0) {
                        struct in_addr_full **dot_servers;
                        size_t n = 0;
                        CLEANUP_ARRAY(dot_servers, n, in_addr_full_array_free);

                        r = dns_resolvers_to_dot_addrs(resolvers, r, &dot_servers, &n);
                        if (r < 0)
                                return r;
                        r = ordered_set_put_dns_servers(s, link->ifindex, dot_servers, n);
                        if (r < 0)
                                return r;
                }
        }

        if (link->dhcp6_lease && link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                const struct in6_addr *addresses;

                r = sd_dhcp6_lease_get_dns(link->dhcp6_lease, &addresses);
                if (r >= 0) {
                        r = ordered_set_put_in6_addrv(s, addresses, r);
                        if (r < 0)
                                return r;
                }
        }

        if (link->dhcp6_lease && link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                sd_dns_resolver *resolvers;

                r = sd_dhcp6_lease_get_dnr(link->dhcp6_lease, &resolvers);
                if (r >= 0) {
                        struct in_addr_full **dot_servers;
                        size_t n = 0;
                        CLEANUP_ARRAY(dot_servers, n, in_addr_full_array_free);

                        r = dns_resolvers_to_dot_addrs(resolvers, r, &dot_servers, &n);
                        if (r < 0)
                                return r;

                        r = ordered_set_put_dns_servers(s, link->ifindex, dot_servers, n);
                        if (r < 0)
                                return r;
                }
        }

        if (link_get_use_dns(link, NETWORK_CONFIG_SOURCE_NDISC)) {
                NDiscRDNSS *a;

                SET_FOREACH(a, link->ndisc_rdnss) {
                        r = ordered_set_put_in6_addrv(s, &a->address, 1);
                        if (r < 0)
                                return r;
                }
        }

        if (link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_NDISC)) {
                NDiscDNR *a;

                SET_FOREACH(a, link->ndisc_dnr) {
                        struct in_addr_full **dot_servers = NULL;
                        size_t n = 0;
                        CLEANUP_ARRAY(dot_servers, n, in_addr_full_array_free);

                        r = dns_resolvers_to_dot_addrs(&a->resolver, 1, &dot_servers, &n);
                        if (r < 0)
                                return r;

                        r = ordered_set_put_dns_servers(s, link->ifindex, dot_servers, n);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int link_put_ntp(Link *link, OrderedSet **s) {
        int r;

        assert(link);
        assert(link->network);
        assert(s);

        if (link->ntp)
                return ordered_set_put_strdupv(s, link->ntp);

        r = ordered_set_put_strdupv(s, link->network->ntp);
        if (r < 0)
                return r;

        if (link->dhcp_lease && link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP4)) {
                const struct in_addr *addresses;

                r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                if (r >= 0) {
                        r = ordered_set_put_in4_addrv(s, addresses, r, in4_addr_is_non_local);
                        if (r < 0)
                                return r;
                }
        }

        if (link->dhcp6_lease && link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                const struct in6_addr *addresses;
                char **fqdn;

                r = sd_dhcp6_lease_get_ntp_addrs(link->dhcp6_lease, &addresses);
                if (r >= 0) {
                        r = ordered_set_put_in6_addrv(s, addresses, r);
                        if (r < 0)
                                return r;
                }

                r = sd_dhcp6_lease_get_ntp_fqdn(link->dhcp6_lease, &fqdn);
                if (r >= 0) {
                        r = ordered_set_put_strdupv(s, fqdn);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int link_put_sip(Link *link, OrderedSet **s) {
        int r;

        assert(link);
        assert(link->network);
        assert(s);

        if (link->dhcp_lease && link->network->dhcp_use_sip) {
                const struct in_addr *addresses;

                r = sd_dhcp_lease_get_sip(link->dhcp_lease, &addresses);
                if (r >= 0) {
                        r = ordered_set_put_in4_addrv(s, addresses, r, in4_addr_is_non_local);
                        if (r < 0)
                                return r;
                }
        }

        if (link->dhcp6_lease && link->network->dhcp6_use_sip) {
                const struct in6_addr *addresses;
                char **domains;

                r = sd_dhcp6_lease_get_sip_addrs(link->dhcp6_lease, &addresses);
                if (r >= 0) {
                        r = ordered_set_put_in6_addrv(s, addresses, r);
                        if (r < 0)
                                return r;
                }

                r = sd_dhcp6_lease_get_sip_domains(link->dhcp6_lease, &domains);
                if (r >= 0) {
                        r = ordered_set_put_strdupv_full(s, &dns_name_hash_ops_free, domains);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int link_put_domains(Link *link, bool is_route, OrderedSet **s) {
        OrderedSet *link_domains, *network_domains;
        UseDomains use_domains;
        int r;

        assert(link);
        assert(link->network);
        assert(s);

        link_domains = is_route ? link->route_domains : link->search_domains;
        network_domains = is_route ? link->network->route_domains : link->network->search_domains;
        use_domains = is_route ? USE_DOMAINS_ROUTE : USE_DOMAINS_YES;

        if (link_domains)
                return ordered_set_put_string_set_full(s, &dns_name_hash_ops_free, link_domains);

        r = ordered_set_put_string_set_full(s, &dns_name_hash_ops_free, network_domains);
        if (r < 0)
                return r;

        if (link->dhcp_lease && link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP4) == use_domains) {
                const char *domainname;
                char **domains;

                r = sd_dhcp_lease_get_domainname(link->dhcp_lease, &domainname);
                if (r >= 0) {
                        r = ordered_set_put_strdup_full(s, &dns_name_hash_ops_free, domainname);
                        if (r < 0)
                                return r;
                }

                r = sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains);
                if (r >= 0) {
                        r = ordered_set_put_strdupv_full(s, &dns_name_hash_ops_free, domains);
                        if (r < 0)
                                return r;
                }
        }

        if (link->dhcp6_lease && link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP6) == use_domains) {
                char **domains;

                r = sd_dhcp6_lease_get_domains(link->dhcp6_lease, &domains);
                if (r >= 0) {
                        r = ordered_set_put_strdupv_full(s, &dns_name_hash_ops_free, domains);
                        if (r < 0)
                                return r;
                }
        }

        if (link_get_use_domains(link, NETWORK_CONFIG_SOURCE_NDISC) == use_domains) {
                NDiscDNSSL *a;

                SET_FOREACH(a, link->ndisc_dnssl) {
                        r = ordered_set_put_strdup_full(s, &dns_name_hash_ops_free, ndisc_dnssl_domain(a));
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int manager_save(Manager *m) {
        _cleanup_ordered_set_free_ OrderedSet *dns = NULL, *ntp = NULL, *sip = NULL, *search_domains = NULL, *route_domains = NULL;
        const char *operstate_str, *carrier_state_str, *address_state_str, *ipv4_address_state_str, *ipv6_address_state_str, *online_state_str;
        LinkOperationalState operstate = LINK_OPERSTATE_OFF;
        LinkCarrierState carrier_state = LINK_CARRIER_STATE_OFF;
        LinkAddressState ipv4_address_state = LINK_ADDRESS_STATE_OFF, ipv6_address_state = LINK_ADDRESS_STATE_OFF,
                address_state = LINK_ADDRESS_STATE_OFF;
        LinkOnlineState online_state;
        size_t links_offline = 0, links_online = 0;
        int r;

        assert(m);

        if (isempty(m->state_file))
                return 0; /* Do not update state file when running in test mode. */

        Link *link;
        HASHMAP_FOREACH(link, m->links_by_index) {
                if (link->flags & IFF_LOOPBACK)
                        continue;

                operstate = MAX(operstate, link->operstate);
                carrier_state = MAX(carrier_state, link->carrier_state);
                address_state = MAX(address_state, link->address_state);
                ipv4_address_state = MAX(ipv4_address_state, link->ipv4_address_state);
                ipv6_address_state = MAX(ipv6_address_state, link->ipv6_address_state);

                if (!link->network)
                        continue;

                if (link->network->required_for_online) {
                        if (link->online_state == LINK_ONLINE_STATE_OFFLINE)
                                links_offline++;
                        else if (link->online_state == LINK_ONLINE_STATE_ONLINE)
                                links_online++;
                }

                r = link_put_dns(link, &dns);
                if (r < 0)
                        return r;

                r = link_put_ntp(link, &ntp);
                if (r < 0)
                        return r;

                r = link_put_sip(link, &sip);
                if (r < 0)
                        return r;

                r = link_put_domains(link, /* is_route= */ false, &search_domains);
                if (r < 0)
                        return r;

                r = link_put_domains(link, /* is_route= */ true, &route_domains);
                if (r < 0)
                        return r;
        }

        if (carrier_state >= LINK_CARRIER_STATE_ENSLAVED)
                carrier_state = LINK_CARRIER_STATE_CARRIER;

        online_state = links_online > 0 ?
                (links_offline > 0 ? LINK_ONLINE_STATE_PARTIAL : LINK_ONLINE_STATE_ONLINE) :
                (links_offline > 0 ? LINK_ONLINE_STATE_OFFLINE : _LINK_ONLINE_STATE_INVALID);

        operstate_str = ASSERT_PTR(link_operstate_to_string(operstate));
        carrier_state_str = ASSERT_PTR(link_carrier_state_to_string(carrier_state));
        address_state_str = ASSERT_PTR(link_address_state_to_string(address_state));
        ipv4_address_state_str = ASSERT_PTR(link_address_state_to_string(ipv4_address_state));
        ipv6_address_state_str = ASSERT_PTR(link_address_state_to_string(ipv6_address_state));

        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        r = fopen_temporary(m->state_file, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "OPER_STATE=%s\n"
                "CARRIER_STATE=%s\n"
                "ADDRESS_STATE=%s\n"
                "IPV4_ADDRESS_STATE=%s\n"
                "IPV6_ADDRESS_STATE=%s\n",
                operstate_str, carrier_state_str, address_state_str, ipv4_address_state_str, ipv6_address_state_str);

        online_state_str = link_online_state_to_string(online_state);
        if (online_state_str)
                fprintf(f, "ONLINE_STATE=%s\n", online_state_str);

        ordered_set_print(f, "DNS=", dns);
        ordered_set_print(f, "NTP=", ntp);
        ordered_set_print(f, "SIP=", sip);
        ordered_set_print(f, "DOMAINS=", search_domains);
        ordered_set_print(f, "ROUTE_DOMAINS=", route_domains);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        r = conservative_rename(temp_path, m->state_file);
        if (r < 0)
                return r;

        temp_path = mfree(temp_path);

        _cleanup_strv_free_ char **p = NULL;

        if (m->operational_state != operstate) {
                m->operational_state = operstate;
                if (strv_extend(&p, "OperationalState") < 0)
                        log_oom();
        }

        if (m->carrier_state != carrier_state) {
                m->carrier_state = carrier_state;
                if (strv_extend(&p, "CarrierState") < 0)
                        log_oom();
        }

        if (m->address_state != address_state) {
                m->address_state = address_state;
                if (strv_extend(&p, "AddressState") < 0)
                        log_oom();
        }

        if (m->ipv4_address_state != ipv4_address_state) {
                m->ipv4_address_state = ipv4_address_state;
                if (strv_extend(&p, "IPv4AddressState") < 0)
                        log_oom();
        }

        if (m->ipv6_address_state != ipv6_address_state) {
                m->ipv6_address_state = ipv6_address_state;
                if (strv_extend(&p, "IPv6AddressState") < 0)
                        log_oom();
        }

        if (m->online_state != online_state) {
                m->online_state = online_state;
                if (strv_extend(&p, "OnlineState") < 0)
                        log_oom();
        }

        if (p) {
                r = manager_send_changed_strv(m, p);
                if (r < 0)
                        log_warning_errno(r, "Could not emit changed properties, ignoring: %m");
        }

        m->dirty = false;

        return 0;
}

static void print_link_hashmap(FILE *f, const char *prefix, Hashmap* h) {
        bool space = false;
        Link *link;

        assert(f);
        assert(prefix);

        if (hashmap_isempty(h))
                return;

        fputs(prefix, f);
        HASHMAP_FOREACH(link, h) {
                if (space)
                        fputc(' ', f);

                fprintf(f, "%i", link->ifindex);
                space = true;
        }

        fputc('\n', f);
}

static void link_save_dns(Link *link, FILE *f, struct in_addr_full **dns, unsigned n_dns, bool *space) {
        bool _space = false;

        if (!space)
                space = &_space;

        for (unsigned j = 0; j < n_dns; j++) {
                const char *str;

                if (dns[j]->ifindex != 0 && dns[j]->ifindex != link->ifindex)
                        continue;

                str = in_addr_full_to_string(dns[j]);
                if (!str)
                        continue;

                if (*space)
                        fputc(' ', f);
                fputs(str, f);
                *space = true;
        }
}

static void serialize_addresses(
                FILE *f,
                const char *lvalue,
                bool *space,
                char **addresses,
                sd_dhcp_lease *lease,
                bool conditional,
                sd_dhcp_lease_server_type_t what,
                sd_dhcp6_lease *lease6,
                bool conditional6,
                int (*lease6_get_addr)(sd_dhcp6_lease*, const struct in6_addr**),
                int (*lease6_get_fqdn)(sd_dhcp6_lease*, char ***)) {

        bool _space = false;
        int r;

        if (!space)
                space = &_space;

        if (lvalue)
                fprintf(f, "%s=", lvalue);
        fputstrv(f, addresses, NULL, space);

        if (lease && conditional) {
                const struct in_addr *lease_addresses;

                r = sd_dhcp_lease_get_servers(lease, what, &lease_addresses);
                if (r > 0)
                        serialize_in_addrs(f, lease_addresses, r, space, in4_addr_is_non_local);
        }

        if (lease6 && conditional6 && lease6_get_addr) {
                const struct in6_addr *in6_addrs;

                r = lease6_get_addr(lease6, &in6_addrs);
                if (r > 0)
                        serialize_in6_addrs(f, in6_addrs, r, space);
        }

        if (lease6 && conditional6 && lease6_get_fqdn) {
                char **in6_hosts;

                r = lease6_get_fqdn(lease6, &in6_hosts);
                if (r > 0)
                        fputstrv(f, in6_hosts, NULL, space);
        }

        if (lvalue)
                fputc('\n', f);
}

static void serialize_resolvers(
                FILE *f,
                const char *lvalue,
                bool *space,
                sd_dhcp_lease *lease,
                bool conditional,
                sd_dhcp6_lease *lease6,
                bool conditional6) {

        bool _space = false;
        if (!space)
                space = &_space;

        if (lvalue)
                fprintf(f, "%s=", lvalue);

        if (lease && conditional) {
                sd_dns_resolver *resolvers;
                _cleanup_strv_free_ char **names = NULL;
                int r;

                r = sd_dhcp_lease_get_dnr(lease, &resolvers);
                if (r < 0 && r != -ENODATA)
                        log_warning_errno(r, "Failed to get DNR from DHCP lease, ignoring: %m");

                if (r > 0) {
                        r = dns_resolvers_to_dot_strv(resolvers, r, &names);
                        if (r < 0)
                                return (void) log_warning_errno(r, "Failed to get DoT servers from DHCP DNR, ignoring: %m");
                        if (r > 0)
                                fputstrv(f, names, NULL, space);
                }
        }

        if (lease6 && conditional6) {
                sd_dns_resolver *resolvers;
                _cleanup_strv_free_ char **names = NULL;
                int r;

                r = sd_dhcp6_lease_get_dnr(lease6, &resolvers);
                if (r >= 0) {
                        r = dns_resolvers_to_dot_strv(resolvers, r, &names);
                        if (r < 0)
                                return (void) log_warning_errno(r, "Failed to get DoT servers from DHCPv6 DNR, ignoring: %m");
                        if (r > 0)
                                fputstrv(f, names, NULL, space);
                }
        }

        if (lvalue)
                fputc('\n', f);

        return;
}

static void link_save_domains(Link *link, FILE *f, OrderedSet *static_domains, UseDomains use_domains) {
        bool space = false;
        const char *p;

        assert(link);
        assert(link->network);
        assert(f);

        ORDERED_SET_FOREACH(p, static_domains)
                fputs_with_separator(f, p, NULL, &space);

        if (use_domains == USE_DOMAINS_NO)
                return;

        if (link->dhcp_lease && link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP4) == use_domains) {
                const char *domainname;
                char **domains;

                if (sd_dhcp_lease_get_domainname(link->dhcp_lease, &domainname) >= 0)
                        fputs_with_separator(f, domainname, NULL, &space);
                if (sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains) >= 0)
                        fputstrv(f, domains, NULL, &space);
        }

        if (link->dhcp6_lease && link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP6) == use_domains) {
                char **domains;

                if (sd_dhcp6_lease_get_domains(link->dhcp6_lease, &domains) >= 0)
                        fputstrv(f, domains, NULL, &space);
        }

        if (link_get_use_domains(link, NETWORK_CONFIG_SOURCE_NDISC) == use_domains) {
                NDiscDNSSL *dd;

                SET_FOREACH(dd, link->ndisc_dnssl)
                        fputs_with_separator(f, ndisc_dnssl_domain(dd), NULL, &space);
        }
}

static int serialize_config_files(FILE *f, const char *prefix, const char *main_config, char * const *dropins) {
        assert(f);
        assert(prefix);
        assert(main_config);

        fprintf(f, "%s_FILE=%s\n", prefix, main_config);

        bool space = false;

        fprintf(f, "%s_FILE_DROPINS=\"", prefix);
        STRV_FOREACH(d, dropins) {
                _cleanup_free_ char *escaped = NULL;

                escaped = xescape(*d, ":");
                if (!escaped)
                        return -ENOMEM;

                fputs_with_separator(f, escaped, ":", &space);
        }
        fputs("\"\n", f);

        return 0;
}

static int link_save(Link *link) {
        const char *admin_state, *oper_state, *carrier_state, *address_state, *ipv4_address_state, *ipv6_address_state;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(link);
        assert(link->manager);

        if (isempty(link->state_file))
                return 0; /* Do not update state files when running in test mode. */

        if (link->state == LINK_STATE_LINGER)
                return 0;

        admin_state = ASSERT_PTR(link_state_to_string(link->state));
        oper_state = ASSERT_PTR(link_operstate_to_string(link->operstate));
        carrier_state = ASSERT_PTR(link_carrier_state_to_string(link->carrier_state));
        address_state = ASSERT_PTR(link_address_state_to_string(link->address_state));
        ipv4_address_state = ASSERT_PTR(link_address_state_to_string(link->ipv4_address_state));
        ipv6_address_state = ASSERT_PTR(link_address_state_to_string(link->ipv6_address_state));

        r = fopen_temporary(link->state_file, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "ADMIN_STATE=%s\n"
                "OPER_STATE=%s\n"
                "CARRIER_STATE=%s\n"
                "ADDRESS_STATE=%s\n"
                "IPV4_ADDRESS_STATE=%s\n"
                "IPV6_ADDRESS_STATE=%s\n",
                admin_state, oper_state, carrier_state, address_state, ipv4_address_state, ipv6_address_state);

        if (link->netdev) {
                r = serialize_config_files(f, "NETDEV", link->netdev->filename, link->netdev->dropins);
                if (r < 0)
                        return r;
        }

        if (link->network) {
                const char *online_state, *captive_portal;
                bool space = false;

                online_state = link_online_state_to_string(link->online_state);
                if (online_state)
                        fprintf(f, "ONLINE_STATE=%s\n", online_state);

                fprintf(f, "REQUIRED_FOR_ONLINE=%s\n",
                        yes_no(link->network->required_for_online));

                LinkOperationalStateRange st;
                link_required_operstate_for_online(link, &st);

                fprintf(f, "REQUIRED_OPER_STATE_FOR_ONLINE=%s:%s\n",
                        link_operstate_to_string(st.min), link_operstate_to_string(st.max));

                fprintf(f, "REQUIRED_FAMILY_FOR_ONLINE=%s\n",
                        link_required_address_family_to_string(link_required_family_for_online(link)));

                fprintf(f, "ACTIVATION_POLICY=%s\n",
                        activation_policy_to_string(link->network->activation_policy));

                r = serialize_config_files(f, "NETWORK", link->network->filename, link->network->dropins);
                if (r < 0)
                        return r;

                /************************************************************/

                fputs("DNS=", f);
                if (link->n_dns != UINT_MAX)
                        link_save_dns(link, f, link->dns, link->n_dns, NULL);
                else {
                        space = false;
                        link_save_dns(link, f, link->network->dns, link->network->n_dns, &space);

                        Bearer *b;

                        if (link_get_bearer(link, &b) >= 0)
                                link_save_dns(link, f, b->dns, b->n_dns, &space);

                        /* DNR resolvers are not required to provide Do53 service, however resolved doesn't
                         * know how to handle such a server so for now Do53 service is required, and
                         * assumed. */
                        serialize_resolvers(f, NULL, &space,
                                            link->dhcp_lease,
                                            link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP4),
                                            link->dhcp6_lease,
                                            link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP6));

                        if (link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_NDISC)) {
                                NDiscDNR *dnr;
                                SET_FOREACH(dnr, link->ndisc_dnr)
                                        serialize_dnr(f, &dnr->resolver, 1, &space);
                        }

                        serialize_addresses(f, NULL, &space,
                                            NULL,
                                            link->dhcp_lease,
                                            link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP4),
                                            SD_DHCP_LEASE_DNS,
                                            link->dhcp6_lease,
                                            link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP6),
                                            sd_dhcp6_lease_get_dns,
                                            NULL);

                        if (link_get_use_dns(link, NETWORK_CONFIG_SOURCE_NDISC)) {
                                NDiscRDNSS *dd;

                                SET_FOREACH(dd, link->ndisc_rdnss)
                                        serialize_in6_addrs(f, &dd->address, 1, &space);
                        }
                }

                fputc('\n', f);

                /************************************************************/

                if (link->ntp) {
                        fputs("NTP=", f);
                        fputstrv(f, link->ntp, NULL, NULL);
                        fputc('\n', f);
                } else
                        serialize_addresses(f, "NTP", NULL,
                                            link->network->ntp,
                                            link->dhcp_lease,
                                            link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP4),
                                            SD_DHCP_LEASE_NTP,
                                            link->dhcp6_lease,
                                            link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP6),
                                            sd_dhcp6_lease_get_ntp_addrs,
                                            sd_dhcp6_lease_get_ntp_fqdn);

                serialize_addresses(f, "SIP", NULL,
                                    NULL,
                                    link->dhcp_lease,
                                    link->network->dhcp_use_sip,
                                    SD_DHCP_LEASE_SIP,
                                    link->dhcp6_lease,
                                    link->network->dhcp6_use_sip,
                                    sd_dhcp6_lease_get_sip_addrs,
                                    sd_dhcp6_lease_get_sip_domains);

                /************************************************************/

                r = link_get_captive_portal(link, &captive_portal);
                if (r < 0)
                        return r;

                if (captive_portal)
                        fprintf(f, "CAPTIVE_PORTAL=%s\n", captive_portal);

                /************************************************************/

                fputs("DOMAINS=", f);
                if (link->search_domains)
                        link_save_domains(link, f, link->search_domains, USE_DOMAINS_NO);
                else
                        link_save_domains(link, f, link->network->search_domains, USE_DOMAINS_YES);
                fputc('\n', f);

                /************************************************************/

                fputs("ROUTE_DOMAINS=", f);
                if (link->route_domains)
                        link_save_domains(link, f, link->route_domains, USE_DOMAINS_NO);
                else
                        link_save_domains(link, f, link->network->route_domains, USE_DOMAINS_ROUTE);
                fputc('\n', f);

                /************************************************************/

                fprintf(f, "LLMNR=%s\n",
                        resolve_support_to_string(link->llmnr >= 0 ? link->llmnr : link->network->llmnr));

                /************************************************************/

                fprintf(f, "MDNS=%s\n",
                        resolve_support_to_string(link->mdns >= 0 ? link->mdns : link->network->mdns));

                /************************************************************/

                int dns_default_route =
                        link->dns_default_route >= 0 ? link->dns_default_route :
                        link->network->dns_default_route;
                if (dns_default_route >= 0)
                        fprintf(f, "DNS_DEFAULT_ROUTE=%s\n", yes_no(dns_default_route));

                /************************************************************/

                DnsOverTlsMode dns_over_tls_mode =
                        link->dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID ? link->dns_over_tls_mode :
                        link->network->dns_over_tls_mode;
                if (dns_over_tls_mode != _DNS_OVER_TLS_MODE_INVALID)
                        fprintf(f, "DNS_OVER_TLS=%s\n", dns_over_tls_mode_to_string(dns_over_tls_mode));

                /************************************************************/

                DnssecMode dnssec_mode =
                        link->dnssec_mode != _DNSSEC_MODE_INVALID ? link->dnssec_mode :
                        link->network->dnssec_mode;
                if (dnssec_mode != _DNSSEC_MODE_INVALID)
                        fprintf(f, "DNSSEC=%s\n", dnssec_mode_to_string(dnssec_mode));

                /************************************************************/

                Set *nta_anchors = link->dnssec_negative_trust_anchors;
                if (set_isempty(nta_anchors))
                        nta_anchors = link->network->dnssec_negative_trust_anchors;

                if (!set_isempty(nta_anchors)) {
                        const char *n;

                        space = false;

                        fputs("DNSSEC_NTA=", f);
                        SET_FOREACH(n, nta_anchors)
                                fputs_with_separator(f, n, NULL, &space);
                        fputc('\n', f);
                }
        }

        print_link_hashmap(f, "CARRIER_BOUND_TO=", link->bound_to_links);
        print_link_hashmap(f, "CARRIER_BOUND_BY=", link->bound_by_links);

        if (link->dhcp_lease) {
                r = dhcp_lease_save(link->dhcp_lease, link->lease_file);
                if (r < 0)
                        return r;

                fprintf(f, "DHCP_LEASE=%s\n", link->lease_file);
        } else
                (void) unlink(link->lease_file);

        r = link_serialize_dhcp6_client(link, f);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        r = conservative_rename(temp_path, link->state_file);
        if (r < 0)
                return r;

        temp_path = mfree(temp_path);

        return 0;
}

void link_dirty(Link *link) {
        assert(link);
        assert(link->manager);

        /* When the manager is in MANAGER_STOPPED, it is not necessary to update state files anymore, as they
         * will be removed soon anyway. Moreover, we cannot call link_ref() in that case. */
        if (link->manager->state == MANAGER_STOPPED)
                return;

        /* The serialized state in /run is no longer up-to-date. */

        /* Also mark manager dirty as link is dirty */
        link->manager->dirty = true;

        /* The interface has been already removed, and the state file for the interface has been or will be
         * removed. The file should not be recreated. Note, even in that case, we may need to recreate the
         * manager state file. Hence the dirty flag for the manager should be set in the above. */
        if (link->state == LINK_STATE_LINGER)
                return;

        if (set_ensure_put(&link->manager->dirty_links, &link_hash_ops, link) <= 0)
                return; /* Ignore allocation errors and don't take another ref if the link was already dirty */

        link_ref(link);
}

void link_clean(Link *link) {
        assert(link);
        assert(link->manager);

        /* The serialized state in /run is up-to-date */

        link_unref(set_remove(link->manager->dirty_links, link));
}

int link_save_and_clean_full(Link *link, bool also_save_manager) {
        int r, k = 0;

        assert(link);
        assert(link->manager);

        if (also_save_manager)
                k = manager_save(link->manager);

        r = link_save(link);
        if (r < 0)
                return r;

        link_clean(link);
        return k;
}

int manager_clean_all(Manager *manager) {
        int r, ret = 0;

        assert(manager);

        if (manager->dirty) {
                r = manager_save(manager);
                if (r < 0)
                        log_warning_errno(r, "Failed to update state file %s, ignoring: %m", manager->state_file);
                RET_GATHER(ret, r);
        }

        Link *link;
        SET_FOREACH(link, manager->dirty_links) {
                r = link_save_and_clean(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to update link state file %s, ignoring: %m", link->state_file);
                RET_GATHER(ret, r);
        }

        return ret;
}
