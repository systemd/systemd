/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <linux/if.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "network-internal.h"
#include "networkd-link.h"
#include "networkd-manager-bus.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-state-file.h"
#include "ordered-set.h"
#include "set.h"
#include "strv.h"
#include "tmpfile-util.h"

static int ordered_set_put_dns_server(OrderedSet **s, int ifindex, struct in_addr_full *dns) {
        const char *p;
        int r;

        assert(s);
        assert(dns);

        if (dns->ifindex != 0 && dns->ifindex != ifindex)
                return 0;

        p = in_addr_full_to_string(dns);
        if (!p)
                return 0;

        r = ordered_set_put_strdup(s, p);
        if (r == -EEXIST)
                return 0;

        return r;
}

static int ordered_set_put_dns_servers(OrderedSet **s, int ifindex, struct in_addr_full **dns, unsigned n) {
        int r, c = 0;

        assert(s);
        assert(dns || n == 0);

        for (unsigned i = 0; i < n; i++) {
                r = ordered_set_put_dns_server(s, ifindex, dns[i]);
                if (r < 0)
                        return r;

                c += r;
        }

        return c;
}

static int ordered_set_put_in4_addr(OrderedSet **s, const struct in_addr *address) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(s);
        assert(address);

        r = in_addr_to_string(AF_INET, (const union in_addr_union*) address, &p);
        if (r < 0)
                return r;

        r = ordered_set_ensure_allocated(s, &string_hash_ops_free);
        if (r < 0)
                return r;

        r = ordered_set_consume(*s, TAKE_PTR(p));
        if (r == -EEXIST)
                return 0;

        return r;
}

static int ordered_set_put_in4_addrv(
                OrderedSet **s,
                const struct in_addr *addresses,
                size_t n,
                bool (*predicate)(const struct in_addr *addr)) {

        int r, c = 0;

        assert(s);
        assert(n == 0 || addresses);

        for (size_t i = 0; i < n; i++) {
                if (predicate && !predicate(&addresses[i]))
                        continue;
                r = ordered_set_put_in4_addr(s, addresses+i);
                if (r < 0)
                        return r;

                c += r;
        }

        return c;
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
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_strv_free_ char **p = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        Link *link;
        int r;

        assert(m);

        if (isempty(m->state_file))
                return 0; /* Do not update state file when running in test mode. */

        HASHMAP_FOREACH(link, m->links_by_index) {
                const struct in_addr *addresses;

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

                /* First add the static configured entries */
                if (link->n_dns != UINT_MAX)
                        r = ordered_set_put_dns_servers(&dns, link->ifindex, link->dns, link->n_dns);
                else
                        r = ordered_set_put_dns_servers(&dns, link->ifindex, link->network->dns, link->network->n_dns);
                if (r < 0)
                        return r;

                r = ordered_set_put_strdupv(&ntp, link->ntp ?: link->network->ntp);
                if (r < 0)
                        return r;

                r = ordered_set_put_string_set(&search_domains, link->search_domains ?: link->network->search_domains);
                if (r < 0)
                        return r;

                r = ordered_set_put_string_set(&route_domains, link->route_domains ?: link->network->route_domains);
                if (r < 0)
                        return r;

                if (!link->dhcp_lease)
                        continue;

                /* Secondly, add the entries acquired via DHCP */
                if (link->network->dhcp_use_dns) {
                        r = sd_dhcp_lease_get_dns(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(&dns, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_ntp) {
                        r = sd_dhcp_lease_get_ntp(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(&ntp, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_sip) {
                        r = sd_dhcp_lease_get_sip(link->dhcp_lease, &addresses);
                        if (r > 0) {
                                r = ordered_set_put_in4_addrv(&sip, addresses, r, in4_addr_is_non_local);
                                if (r < 0)
                                        return r;
                        } else if (r < 0 && r != -ENODATA)
                                return r;
                }

                if (link->network->dhcp_use_domains != DHCP_USE_DOMAINS_NO) {
                        OrderedSet **target_domains;
                        const char *domainname;
                        char **domains = NULL;

                        target_domains = link->network->dhcp_use_domains == DHCP_USE_DOMAINS_YES ? &search_domains : &route_domains;
                        r = sd_dhcp_lease_get_domainname(link->dhcp_lease, &domainname);
                        if (r >= 0) {
                                r = ordered_set_put_strdup(target_domains, domainname);
                                if (r < 0)
                                        return r;
                        } else if (r != -ENODATA)
                                return r;

                        r = sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains);
                        if (r >= 0) {
                                r = ordered_set_put_strdupv(target_domains, domains);
                                if (r < 0)
                                        return r;
                        } else if (r != -ENODATA)
                                return r;
                }
        }

        if (carrier_state >= LINK_CARRIER_STATE_ENSLAVED)
                carrier_state = LINK_CARRIER_STATE_CARRIER;

        online_state = links_online > 0 ?
                (links_offline > 0 ? LINK_ONLINE_STATE_PARTIAL : LINK_ONLINE_STATE_ONLINE) :
                (links_offline > 0 ? LINK_ONLINE_STATE_OFFLINE : _LINK_ONLINE_STATE_INVALID);

        operstate_str = link_operstate_to_string(operstate);
        assert(operstate_str);

        carrier_state_str = link_carrier_state_to_string(carrier_state);
        assert(carrier_state_str);

        address_state_str = link_address_state_to_string(address_state);
        assert(address_state_str);

        ipv4_address_state_str = link_address_state_to_string(ipv4_address_state);
        assert(ipv4_address_state_str);

        ipv6_address_state_str = link_address_state_to_string(ipv6_address_state);
        assert(ipv6_address_state_str);

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

static void link_save_domains(Link *link, FILE *f, OrderedSet *static_domains, DHCPUseDomains use_domains) {
        bool space = false;
        const char *p;

        assert(link);
        assert(link->network);
        assert(f);

        ORDERED_SET_FOREACH(p, static_domains)
                fputs_with_space(f, p, NULL, &space);

        if (use_domains == DHCP_USE_DOMAINS_NO)
                return;

        if (link->dhcp_lease && link->network->dhcp_use_domains == use_domains) {
                const char *domainname;
                char **domains;

                if (sd_dhcp_lease_get_domainname(link->dhcp_lease, &domainname) >= 0)
                        fputs_with_space(f, domainname, NULL, &space);
                if (sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains) >= 0)
                        fputstrv(f, domains, NULL, &space);
        }

        if (link->dhcp6_lease && link->network->dhcp6_use_domains == use_domains) {
                char **domains;

                if (sd_dhcp6_lease_get_domains(link->dhcp6_lease, &domains) >= 0)
                        fputstrv(f, domains, NULL, &space);
        }

        if (link->network->ipv6_accept_ra_use_domains == use_domains) {
                NDiscDNSSL *dd;

                SET_FOREACH(dd, link->ndisc_dnssl)
                        fputs_with_space(f, NDISC_DNSSL_DOMAIN(dd), NULL, &space);
        }
}

int link_save(Link *link) {
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

        link_lldp_save(link);

        admin_state = link_state_to_string(link->state);
        assert(admin_state);

        oper_state = link_operstate_to_string(link->operstate);
        assert(oper_state);

        carrier_state = link_carrier_state_to_string(link->carrier_state);
        assert(carrier_state);

        address_state = link_address_state_to_string(link->address_state);
        assert(address_state);

        ipv4_address_state = link_address_state_to_string(link->ipv4_address_state);
        assert(ipv4_address_state);

        ipv6_address_state = link_address_state_to_string(link->ipv6_address_state);
        assert(ipv6_address_state);

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

        if (link->network) {
                const char *online_state;
                bool space;

                online_state = link_online_state_to_string(link->online_state);
                if (online_state)
                        fprintf(f, "ONLINE_STATE=%s\n", online_state);

                fprintf(f, "REQUIRED_FOR_ONLINE=%s\n",
                        yes_no(link->network->required_for_online));

                LinkOperationalStateRange st = link->network->required_operstate_for_online;
                fprintf(f, "REQUIRED_OPER_STATE_FOR_ONLINE=%s%s%s\n",
                        strempty(link_operstate_to_string(st.min)),
                        st.max != LINK_OPERSTATE_RANGE_DEFAULT.max ? ":" : "",
                        st.max != LINK_OPERSTATE_RANGE_DEFAULT.max ? strempty(link_operstate_to_string(st.max)) : "");

                fprintf(f, "REQUIRED_FAMILY_FOR_ONLINE=%s\n",
                        link_required_address_family_to_string(link->network->required_family_for_online));

                fprintf(f, "ACTIVATION_POLICY=%s\n",
                        activation_policy_to_string(link->network->activation_policy));

                fprintf(f, "NETWORK_FILE=%s\n", link->network->filename);

                /************************************************************/

                fputs("DNS=", f);
                if (link->n_dns != UINT_MAX)
                        link_save_dns(link, f, link->dns, link->n_dns, NULL);
                else {
                        space = false;
                        link_save_dns(link, f, link->network->dns, link->network->n_dns, &space);

                        serialize_addresses(f, NULL, &space,
                                            NULL,
                                            link->dhcp_lease,
                                            link->network->dhcp_use_dns,
                                            SD_DHCP_LEASE_DNS,
                                            link->dhcp6_lease,
                                            link->network->dhcp6_use_dns,
                                            sd_dhcp6_lease_get_dns,
                                            NULL);

                        if (link->network->ipv6_accept_ra_use_dns) {
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
                                            link->network->dhcp_use_ntp,
                                            SD_DHCP_LEASE_NTP,
                                            link->dhcp6_lease,
                                            link->network->dhcp6_use_ntp,
                                            sd_dhcp6_lease_get_ntp_addrs,
                                            sd_dhcp6_lease_get_ntp_fqdn);

                serialize_addresses(f, "SIP", NULL,
                                    NULL,
                                    link->dhcp_lease,
                                    link->network->dhcp_use_sip,
                                    SD_DHCP_LEASE_SIP,
                                    NULL, false, NULL, NULL);

                /************************************************************/

                fputs("DOMAINS=", f);
                if (link->search_domains)
                        link_save_domains(link, f, link->search_domains, DHCP_USE_DOMAINS_NO);
                else
                        link_save_domains(link, f, link->network->search_domains, DHCP_USE_DOMAINS_YES);
                fputc('\n', f);

                /************************************************************/

                fputs("ROUTE_DOMAINS=", f);
                if (link->route_domains)
                        link_save_domains(link, f, link->route_domains, DHCP_USE_DOMAINS_NO);
                else
                        link_save_domains(link, f, link->network->route_domains, DHCP_USE_DOMAINS_ROUTE);
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

                        fputs("DNSSEC_NTA=", f);
                        space = false;
                        SET_FOREACH(n, nta_anchors)
                                fputs_with_space(f, n, NULL, &space);
                        fputc('\n', f);
                }
        }

        print_link_hashmap(f, "CARRIER_BOUND_TO=", link->bound_to_links);
        print_link_hashmap(f, "CARRIER_BOUND_BY=", link->bound_by_links);

        if (link->dhcp_lease) {
                r = dhcp_lease_save(link->dhcp_lease, link->lease_file);
                if (r < 0)
                        return r;

                fprintf(f,
                        "DHCP_LEASE=%s\n",
                        link->lease_file);
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
        int r;

        assert(link);
        assert(link->manager);

        /* The serialized state in /run is no longer up-to-date. */

        /* Also mark manager dirty as link is dirty */
        link->manager->dirty = true;

        r = set_ensure_put(&link->manager->dirty_links, NULL, link);
        if (r <= 0)
                /* Ignore allocation errors and don't take another ref if the link was already dirty */
                return;
        link_ref(link);
}

void link_clean(Link *link) {
        assert(link);
        assert(link->manager);

        /* The serialized state in /run is up-to-date */

        link_unref(set_remove(link->manager->dirty_links, link));
}

int link_save_and_clean(Link *link) {
        int r;

        r = link_save(link);
        if (r < 0)
                return r;

        link_clean(link);
        return 0;
}
