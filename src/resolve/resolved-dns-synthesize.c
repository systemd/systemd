/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "env-util.h"
#include "hostname-util.h"
#include "local-addresses.h"
#include "missing_network.h"
#include "resolved-dns-synthesize.h"

int dns_synthesize_ifindex(int ifindex) {

        /* When the caller asked for resolving on a specific
         * interface, we synthesize the answer for that
         * interface. However, if nothing specific was claimed and we
         * only return localhost RRs, we synthesize the answer for
         * localhost. */

        if (ifindex > 0)
                return ifindex;

        return LOOPBACK_IFINDEX;
}

int dns_synthesize_family(uint64_t flags) {

        /* Picks an address family depending on set flags. This is
         * purely for synthesized answers, where the family we return
         * for the reply should match what was requested in the
         * question, even though we are synthesizing the answer
         * here. */

        if (!(flags & SD_RESOLVED_DNS)) {
                if (flags & (SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_MDNS_IPV4))
                        return AF_INET;
                if (flags & (SD_RESOLVED_LLMNR_IPV6|SD_RESOLVED_MDNS_IPV6))
                        return AF_INET6;
        }

        return AF_UNSPEC;
}

DnsProtocol dns_synthesize_protocol(uint64_t flags) {

        /* Similar as dns_synthesize_family() but does this for the
         * protocol. If resolving via DNS was requested, we claim it
         * was DNS. Similar, if nothing specific was
         * requested. However, if only resolving via LLMNR was
         * requested we return that. */

        if (flags & SD_RESOLVED_DNS)
                return DNS_PROTOCOL_DNS;
        if (flags & SD_RESOLVED_LLMNR)
                return DNS_PROTOCOL_LLMNR;
        if (flags & SD_RESOLVED_MDNS)
                return DNS_PROTOCOL_MDNS;

        return DNS_PROTOCOL_DNS;
}

static int synthesize_localhost_rr(Manager *m, const DnsResourceKey *key, int ifindex, DnsAnswer **answer) {
        int r;

        assert(m);
        assert(key);
        assert(answer);

        r = dns_answer_reserve(answer, 2);
        if (r < 0)
                return r;

        if (IN_SET(key->type, DNS_TYPE_A, DNS_TYPE_ANY)) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, dns_resource_key_name(key));
                if (!rr)
                        return -ENOMEM;

                rr->a.in_addr.s_addr = htobe32(INADDR_LOOPBACK);

                r = dns_answer_add(*answer, rr, dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED, NULL);
                if (r < 0)
                        return r;
        }

        if (IN_SET(key->type, DNS_TYPE_AAAA, DNS_TYPE_ANY) && socket_ipv6_is_enabled()) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, dns_resource_key_name(key));
                if (!rr)
                        return -ENOMEM;

                rr->aaaa.in6_addr = in6addr_loopback;

                r = dns_answer_add(*answer, rr, dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int answer_add_ptr(DnsAnswer **answer, const char *from, const char *to, int ifindex, DnsAnswerFlags flags) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, from);
        if (!rr)
                return -ENOMEM;

        rr->ptr.name = strdup(to);
        if (!rr->ptr.name)
                return -ENOMEM;

        return dns_answer_add(*answer, rr, ifindex, flags, NULL);
}

static int synthesize_localhost_ptr(Manager *m, const DnsResourceKey *key, int ifindex, DnsAnswer **answer) {
        int r;

        assert(m);
        assert(key);
        assert(answer);

        if (IN_SET(key->type, DNS_TYPE_PTR, DNS_TYPE_ANY)) {
                r = dns_answer_reserve(answer, 1);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, dns_resource_key_name(key), "localhost", dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int answer_add_addresses_rr(
                DnsAnswer **answer,
                const char *name,
                struct local_address *addresses,
                unsigned n_addresses) {

        unsigned j;
        int r;

        assert(answer);
        assert(name);

        r = dns_answer_reserve(answer, n_addresses);
        if (r < 0)
                return r;

        for (j = 0; j < n_addresses; j++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                r = dns_resource_record_new_address(&rr, addresses[j].family, &addresses[j].address, name);
                if (r < 0)
                        return r;

                r = dns_answer_add(*answer, rr, addresses[j].ifindex, DNS_ANSWER_AUTHENTICATED, NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int answer_add_addresses_ptr(
                DnsAnswer **answer,
                const char *name,
                struct local_address *addresses,
                unsigned n_addresses,
                int af, const union in_addr_union *match) {

        bool added = false;
        unsigned j;
        int r;

        assert(answer);
        assert(name);

        for (j = 0; j < n_addresses; j++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                if (af != AF_UNSPEC) {

                        if (addresses[j].family != af)
                                continue;

                        if (match && !in_addr_equal(af, match, &addresses[j].address))
                                continue;
                }

                r = dns_answer_reserve(answer, 1);
                if (r < 0)
                        return r;

                r = dns_resource_record_new_reverse(&rr, addresses[j].family, &addresses[j].address, name);
                if (r < 0)
                        return r;

                r = dns_answer_add(*answer, rr, addresses[j].ifindex, DNS_ANSWER_AUTHENTICATED, NULL);
                if (r < 0)
                        return r;

                added = true;
        }

        return added;
}

static int synthesize_system_hostname_rr(Manager *m, const DnsResourceKey *key, int ifindex, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n = 0, af;

        assert(m);
        assert(key);
        assert(answer);

        af = dns_type_to_af(key->type);
        if (af >= 0) {
                n = local_addresses(m->rtnl, ifindex, af, &addresses);
                if (n < 0)
                        return n;

                if (n == 0) {
                        struct local_address buffer[2];

                        /* If we have no local addresses then use ::1
                         * and 127.0.0.2 as local ones. */

                        if (IN_SET(af, AF_INET, AF_UNSPEC))
                                buffer[n++] = (struct local_address) {
                                        .family = AF_INET,
                                        .ifindex = dns_synthesize_ifindex(ifindex),
                                        .address.in.s_addr = htobe32(0x7F000002),
                                };

                        if (IN_SET(af, AF_INET6, AF_UNSPEC) && socket_ipv6_is_enabled())
                                buffer[n++] = (struct local_address) {
                                        .family = AF_INET6,
                                        .ifindex = dns_synthesize_ifindex(ifindex),
                                        .address.in6 = in6addr_loopback,
                                };

                        return answer_add_addresses_rr(answer,
                                                       dns_resource_key_name(key),
                                                       buffer, n);
                }
        }

        return answer_add_addresses_rr(answer, dns_resource_key_name(key), addresses, n);
}

static int synthesize_system_hostname_ptr(Manager *m, int af, const union in_addr_union *address, int ifindex, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        bool added = false;
        int n, r;

        assert(m);
        assert(address);
        assert(answer);

        if (af == AF_INET && address->in.s_addr == htobe32(0x7F000002)) {

                /* Always map the IPv4 address 127.0.0.2 to the local hostname, in addition to "localhost": */

                r = dns_answer_reserve(answer, 4);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", m->full_hostname, dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", m->llmnr_hostname, dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", m->mdns_hostname, dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                r = answer_add_ptr(answer, "2.0.0.127.in-addr.arpa", "localhost", dns_synthesize_ifindex(ifindex), DNS_ANSWER_AUTHENTICATED);
                if (r < 0)
                        return r;

                return 1;
        }

        n = local_addresses(m->rtnl, ifindex, af, &addresses);
        if (n <= 0)
                return n;

        r = answer_add_addresses_ptr(answer, m->full_hostname, addresses, n, af, address);
        if (r < 0)
                return r;
        if (r > 0)
                added = true;

        r = answer_add_addresses_ptr(answer, m->llmnr_hostname, addresses, n, af, address);
        if (r < 0)
                return r;
        if (r > 0)
                added = true;

        r = answer_add_addresses_ptr(answer, m->mdns_hostname, addresses, n, af, address);
        if (r < 0)
                return r;
        if (r > 0)
                added = true;

        return added;
}

static int synthesize_gateway_rr(
                Manager *m,
                const DnsResourceKey *key,
                int ifindex,
                int (*lookup)(sd_netlink *context, int ifindex, int af, struct local_address **ret), /* either local_gateways() or local_outbound() */
                DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n = 0, af, r;

        assert(m);
        assert(key);
        assert(lookup);
        assert(answer);

        af = dns_type_to_af(key->type);
        if (af >= 0) {
                n = lookup(m->rtnl, ifindex, af, &addresses);
                if (n < 0) /* < 0 means: error */
                        return n;

                if (n == 0) { /* == 0 means we have no gateway */
                        /* See if there's a gateway on the other protocol */
                        if (af == AF_INET)
                                n = lookup(m->rtnl, ifindex, AF_INET6, NULL);
                        else {
                                assert(af == AF_INET6);
                                n = lookup(m->rtnl, ifindex, AF_INET, NULL);
                        }
                        if (n <= 0) /* error (if < 0) or really no gateway at all (if == 0) */
                                return n;

                        /* We have a gateway on the other protocol. Let's return > 0 without adding any RR to
                         * the answer, i.e. synthesize NODATA (and not NXDOMAIN!) */
                        return 1;
                }
        }

        r = answer_add_addresses_rr(answer, dns_resource_key_name(key), addresses, n);
        if (r < 0)
                return r;

        return 1; /* > 0 means: we have some gateway */
}

static int synthesize_gateway_ptr(Manager *m, int af, const union in_addr_union *address, int ifindex, DnsAnswer **answer) {
        _cleanup_free_ struct local_address *addresses = NULL;
        int n;

        assert(m);
        assert(address);
        assert(answer);

        n = local_gateways(m->rtnl, ifindex, af, &addresses);
        if (n <= 0)
                return n;

        return answer_add_addresses_ptr(answer, "_gateway", addresses, n, af, address);
}

int dns_synthesize_answer(
                Manager *m,
                DnsQuestion *q,
                int ifindex,
                DnsAnswer **ret) {

        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsResourceKey *key;
        bool found = false, nxdomain = false;
        int r;

        assert(m);
        assert(q);

        DNS_QUESTION_FOREACH(key, q) {
                union in_addr_union address;
                const char *name;
                int af;

                if (!IN_SET(key->class, DNS_CLASS_IN, DNS_CLASS_ANY))
                        continue;

                name = dns_resource_key_name(key);

                if (dns_name_is_empty(name)) {
                        /* Do nothing. */

                } else if (dns_name_dont_resolve(name)) {
                        /* Synthesize NXDOMAIN for some of the domains in RFC6303 + RFC6761 */
                        nxdomain = true;
                        continue;

                } else if (is_localhost(name)) {

                        r = synthesize_localhost_rr(m, key, ifindex, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize localhost RRs: %m");

                } else if (manager_is_own_hostname(m, name)) {

                        if (getenv_bool("SYSTEMD_RESOLVED_SYNTHESIZE_HOSTNAME") == 0)
                                continue;
                        r = synthesize_system_hostname_rr(m, key, ifindex, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize system hostname RRs: %m");

                } else if (is_gateway_hostname(name)) {

                        r = synthesize_gateway_rr(m, key, ifindex, local_gateways, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize gateway RRs: %m");
                        if (r == 0) { /* if we have no gateway return NXDOMAIN */
                                nxdomain = true;
                                continue;
                        }

                } else if (is_outbound_hostname(name)) {

                        r = synthesize_gateway_rr(m, key, ifindex, local_outbounds, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize outbound RRs: %m");
                        if (r == 0) { /* if we have no gateway return NXDOMAIN */
                                nxdomain = true;
                                continue;
                        }

                } else if ((dns_name_endswith(name, "127.in-addr.arpa") > 0 && dns_name_equal(name, "2.0.0.127.in-addr.arpa") == 0) ||
                           dns_name_equal(name, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") > 0) {

                        r = synthesize_localhost_ptr(m, key, ifindex, &answer);
                        if (r < 0)
                                return log_error_errno(r, "Failed to synthesize localhost PTR RRs: %m");

                } else if (dns_name_address(name, &af, &address) > 0) {
                        int v, w;

                        if (getenv_bool("SYSTEMD_RESOLVED_SYNTHESIZE_HOSTNAME") == 0)
                                continue;

                        v = synthesize_system_hostname_ptr(m, af, &address, ifindex, &answer);
                        if (v < 0)
                                return log_error_errno(v, "Failed to synthesize system hostname PTR RR: %m");

                        w = synthesize_gateway_ptr(m, af, &address, ifindex, &answer);
                        if (w < 0)
                                return log_error_errno(w, "Failed to synthesize gateway hostname PTR RR: %m");

                        if (v == 0 && w == 0) /* This IP address is neither a local one nor a gateway */
                                continue;

                        /* Note that we never synthesize reverse PTR for _outbound, since those are local
                         * addresses and thus mapped to the local hostname anyway, hence they already have a
                         * mapping. */

                } else
                        continue;

                found = true;
        }

        if (found) {

                if (ret)
                        *ret = TAKE_PTR(answer);

                return 1;
        } else if (nxdomain)
                return -ENXIO;

        return 0;
}
