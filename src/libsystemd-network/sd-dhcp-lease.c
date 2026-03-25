/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <arpa/inet.h>
#include <sys/stat.h>

#include "sd-dhcp-lease.h"

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "dhcp-option.h"
#include "dns-def.h"
#include "dns-domain.h"
#include "dns-resolver-internal.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "network-common.h"
#include "network-internal.h"
#include "parse-util.h"
#include "sort-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "unaligned.h"

void dhcp_lease_set_timestamp(sd_dhcp_lease *lease, const triple_timestamp *timestamp) {
        assert(lease);

        if (timestamp && triple_timestamp_is_set(timestamp))
                lease->timestamp = *timestamp;
        else
                triple_timestamp_now(&lease->timestamp);
}

int sd_dhcp_lease_get_timestamp(sd_dhcp_lease *lease, clockid_t clock, uint64_t *ret) {
        assert_return(lease, -EINVAL);
        assert_return(TRIPLE_TIMESTAMP_HAS_CLOCK(clock), -EOPNOTSUPP);
        assert_return(clock_supported(clock), -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        if (!triple_timestamp_is_set(&lease->timestamp))
                return -ENODATA;

        *ret = triple_timestamp_by_clock(&lease->timestamp, clock);
        return 0;
}

int sd_dhcp_lease_get_address(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->address == 0)
                return -ENODATA;

        addr->s_addr = lease->address;
        return 0;
}

int sd_dhcp_lease_get_broadcast(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (!lease->have_broadcast)
                return -ENODATA;

        addr->s_addr = lease->broadcast;
        return 0;
}

int sd_dhcp_lease_get_lifetime(sd_dhcp_lease *lease, uint64_t *ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (lease->lifetime <= 0)
                return -ENODATA;

        *ret = lease->lifetime;
        return 0;
}

int sd_dhcp_lease_get_t1(sd_dhcp_lease *lease, uint64_t *ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (lease->t1 <= 0)
                return -ENODATA;

        *ret = lease->t1;
        return 0;
}

int sd_dhcp_lease_get_t2(sd_dhcp_lease *lease, uint64_t *ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (lease->t2 <= 0)
                return -ENODATA;

        *ret = lease->t2;
        return 0;
}

#define DEFINE_GET_TIMESTAMP(name)                                      \
        int sd_dhcp_lease_get_##name##_timestamp(                       \
                        sd_dhcp_lease *lease,                           \
                        clockid_t clock,                                \
                        uint64_t *ret) {                                \
                                                                        \
                usec_t t, timestamp;                                    \
                int r;                                                  \
                                                                        \
                assert_return(ret, -EINVAL);                            \
                                                                        \
                r = sd_dhcp_lease_get_##name(lease, &t);                \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = sd_dhcp_lease_get_timestamp(lease, clock, &timestamp); \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                *ret = usec_add(t, timestamp);                          \
                return 0;                                               \
        }

DEFINE_GET_TIMESTAMP(lifetime);
DEFINE_GET_TIMESTAMP(t1);
DEFINE_GET_TIMESTAMP(t2);

int sd_dhcp_lease_get_mtu(sd_dhcp_lease *lease, uint16_t *mtu) {
        assert_return(lease, -EINVAL);
        assert_return(mtu, -EINVAL);

        if (lease->mtu <= 0)
                return -ENODATA;

        *mtu = lease->mtu;
        return 0;
}

int sd_dhcp_lease_get_servers(
                sd_dhcp_lease *lease,
                sd_dhcp_lease_server_type_t what,
                const struct in_addr **addr) {

        assert_return(lease, -EINVAL);
        assert_return(what >= 0, -EINVAL);
        assert_return(what < _SD_DHCP_LEASE_SERVER_TYPE_MAX, -EINVAL);

        if (lease->servers[what].size <= 0)
                return -ENODATA;

        if (addr)
                *addr = lease->servers[what].addr;

        return (int) lease->servers[what].size;
}

int sd_dhcp_lease_get_dns(sd_dhcp_lease *lease, const struct in_addr **addr) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_DNS, addr);
}
int sd_dhcp_lease_get_ntp(sd_dhcp_lease *lease, const struct in_addr **addr) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_NTP, addr);
}
int sd_dhcp_lease_get_sip(sd_dhcp_lease *lease, const struct in_addr **addr) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_SIP, addr);
}
int sd_dhcp_lease_get_pop3(sd_dhcp_lease *lease, const struct in_addr **addr) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_POP3, addr);
}
int sd_dhcp_lease_get_smtp(sd_dhcp_lease *lease, const struct in_addr **addr) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_SMTP, addr);
}
int sd_dhcp_lease_get_lpr(sd_dhcp_lease *lease, const struct in_addr **addr) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_LPR, addr);
}

int sd_dhcp_lease_get_domainname(sd_dhcp_lease *lease, const char **domainname) {
        assert_return(lease, -EINVAL);
        assert_return(domainname, -EINVAL);

        if (!lease->domainname)
                return -ENODATA;

        *domainname = lease->domainname;
        return 0;
}

int sd_dhcp_lease_get_hostname(sd_dhcp_lease *lease, const char **hostname) {
        assert_return(lease, -EINVAL);
        assert_return(hostname, -EINVAL);

        /* FQDN option (81) always takes precedence. */

        if (lease->fqdn)
                *hostname = lease->fqdn;
        else if (lease->hostname)
                *hostname = lease->hostname;
        else
                return -ENODATA;

        return 0;
}

int sd_dhcp_lease_get_root_path(sd_dhcp_lease *lease, const char **root_path) {
        assert_return(lease, -EINVAL);
        assert_return(root_path, -EINVAL);

        if (!lease->root_path)
                return -ENODATA;

        *root_path = lease->root_path;
        return 0;
}

int sd_dhcp_lease_get_captive_portal(sd_dhcp_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->captive_portal)
                return -ENODATA;

        *ret = lease->captive_portal;
        return 0;
}

int sd_dhcp_lease_get_dnr(sd_dhcp_lease *lease, sd_dns_resolver **ret_resolvers) {
        assert_return(lease, -EINVAL);
        assert_return(ret_resolvers, -EINVAL);

        if (!lease->dnr)
                return -ENODATA;

        *ret_resolvers = lease->dnr;
        return lease->n_dnr;
}

int sd_dhcp_lease_get_router(sd_dhcp_lease *lease, const struct in_addr **addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->router_size <= 0)
                return -ENODATA;

        *addr = lease->router;
        return (int) lease->router_size;
}

int sd_dhcp_lease_get_netmask(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (!lease->have_subnet_mask)
                return -ENODATA;

        addr->s_addr = lease->subnet_mask;
        return 0;
}

int sd_dhcp_lease_get_prefix(sd_dhcp_lease *lease, struct in_addr *ret_prefix, uint8_t *ret_prefixlen) {
        struct in_addr address, netmask;
        uint8_t prefixlen;
        int r;

        assert_return(lease, -EINVAL);

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0)
                return r;

        r = sd_dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0)
                return r;

        prefixlen = in4_addr_netmask_to_prefixlen(&netmask);

        r = in4_addr_mask(&address, prefixlen);
        if (r < 0)
                return r;

        if (ret_prefix)
                *ret_prefix = address;
        if (ret_prefixlen)
                *ret_prefixlen = prefixlen;
        return 0;
}

int sd_dhcp_lease_get_server_identifier(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->server_address == 0)
                return -ENODATA;

        addr->s_addr = lease->server_address;
        return 0;
}

int sd_dhcp_lease_get_next_server(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->next_server == 0)
                return -ENODATA;

        addr->s_addr = lease->next_server;
        return 0;
}

/*
 * The returned routes array must be freed by the caller.
 * Route objects have the same lifetime of the lease and must not be freed.
 */
static int dhcp_lease_get_routes(sd_dhcp_route *routes, size_t n_routes, sd_dhcp_route ***ret) {
        assert(routes || n_routes == 0);

        if (n_routes <= 0)
                return -ENODATA;

        if (ret) {
                sd_dhcp_route **buf;

                buf = new(sd_dhcp_route*, n_routes);
                if (!buf)
                        return -ENOMEM;

                for (size_t i = 0; i < n_routes; i++)
                        buf[i] = &routes[i];

                *ret = buf;
        }

        return (int) n_routes;
}

int sd_dhcp_lease_get_static_routes(sd_dhcp_lease *lease, sd_dhcp_route ***ret) {
        assert_return(lease, -EINVAL);

        return dhcp_lease_get_routes(lease->static_routes, lease->n_static_routes, ret);
}

int sd_dhcp_lease_get_classless_routes(sd_dhcp_lease *lease, sd_dhcp_route ***ret) {
        assert_return(lease, -EINVAL);

        return dhcp_lease_get_routes(lease->classless_routes, lease->n_classless_routes, ret);
}

int sd_dhcp_lease_get_search_domains(sd_dhcp_lease *lease, char ***domains) {
        size_t r;

        assert_return(lease, -EINVAL);
        assert_return(domains, -EINVAL);

        r = strv_length(lease->search_domains);
        if (r > 0) {
                *domains = lease->search_domains;
                return (int) r;
        }

        return -ENODATA;
}

int sd_dhcp_lease_get_6rd(
                sd_dhcp_lease *lease,
                uint8_t *ret_ipv4masklen,
                uint8_t *ret_prefixlen,
                struct in6_addr *ret_prefix,
                const struct in_addr **ret_br_addresses,
                size_t *ret_n_br_addresses) {

        assert_return(lease, -EINVAL);

        if (lease->sixrd_n_br_addresses <= 0)
                return -ENODATA;

        if (ret_ipv4masklen)
                *ret_ipv4masklen = lease->sixrd_ipv4masklen;
        if (ret_prefixlen)
                *ret_prefixlen = lease->sixrd_prefixlen;
        if (ret_prefix)
                *ret_prefix = lease->sixrd_prefix;
        if (ret_br_addresses)
                *ret_br_addresses = lease->sixrd_br_addresses;
        if (ret_n_br_addresses)
                *ret_n_br_addresses = lease->sixrd_n_br_addresses;

        return 0;
}

int sd_dhcp_lease_has_6rd(sd_dhcp_lease *lease) {
        return lease && lease->sixrd_n_br_addresses > 0;
}

int sd_dhcp_lease_get_vendor_specific(sd_dhcp_lease *lease, const void **data, size_t *data_len) {
        assert_return(lease, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(data_len, -EINVAL);

        if (lease->vendor_specific_len <= 0)
                return -ENODATA;

        *data = lease->vendor_specific;
        *data_len = lease->vendor_specific_len;
        return 0;
}

static sd_dhcp_lease *dhcp_lease_free(sd_dhcp_lease *lease) {
        struct sd_dhcp_raw_option *option;

        assert(lease);

        while ((option = LIST_POP(options, lease->private_options))) {
                free(option->data);
                free(option);
        }

        free(lease->root_path);
        free(lease->router);
        free(lease->timezone);
        free(lease->hostname);
        free(lease->fqdn);
        free(lease->domainname);
        free(lease->captive_portal);

        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(lease->servers[i].addr);

        dns_resolver_done_many(lease->dnr, lease->n_dnr);
        free(lease->static_routes);
        free(lease->classless_routes);
        free(lease->vendor_specific);
        strv_free(lease->search_domains);
        free(lease->sixrd_br_addresses);
        return mfree(lease);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_lease, sd_dhcp_lease, dhcp_lease_free);

static int lease_parse_be32_seconds(const uint8_t *option, size_t len, bool max_as_infinity, usec_t *ret) {
        assert(option);
        assert(ret);

        if (len != 4)
                return -EINVAL;

        *ret = unaligned_be32_sec_to_usec(option, max_as_infinity);
        return 0;
}

static int lease_parse_u16(const uint8_t *option, size_t len, uint16_t *ret, uint16_t min) {
        assert(option);
        assert(ret);

        if (len != 2)
                return -EINVAL;

        *ret = unaligned_read_be16((be16_t*) option);
        if (*ret < min)
                *ret = min;

        return 0;
}

static int lease_parse_be32(const uint8_t *option, size_t len, be32_t *ret) {
        assert(option);
        assert(ret);

        if (len != 4)
                return -EINVAL;

        memcpy(ret, option, 4);
        return 0;
}

static int lease_parse_domain(const uint8_t *option, size_t len, char **domain) {
        _cleanup_free_ char *name = NULL, *normalized = NULL;
        int r;

        assert(option);
        assert(domain);

        r = dhcp_option_parse_string(option, len, &name);
        if (r < 0)
                return r;
        if (!name) {
                *domain = mfree(*domain);
                return 0;
        }

        r = dns_name_normalize(name, 0, &normalized);
        if (r < 0)
                return r;

        if (is_localhost(normalized))
                return -EINVAL;

        if (dns_name_is_root(normalized))
                return -EINVAL;

        return free_and_replace(*domain, normalized);
}

static int lease_parse_fqdn(const uint8_t *option, size_t len, char **fqdn) {
        _cleanup_free_ char *name = NULL, *normalized = NULL;
        int r;

        assert(option);
        assert(fqdn);

        /* RFC 4702 Section 2
         *
         * Byte 0: Flags (S: server should perform A RR updates, O: override existing A RR,
         *                E: encoding (0=ASCII, 1=Wire format), N: no server updates)
         * Byte 1: RCODE1 (ignored on receipt)
         * Byte 2: RCODE2 (ignored on receipt)
         * Bytes 3+: Domain Name */

        if (len <= 3)
                return -EBADMSG;

        size_t data_len = len - 3;
        const uint8_t *data = option + 3;

        /* In practice, many servers send DNS wire format regardless of the E flag, so ignore and try wire
         * format first, then fall back to ASCII if that fails. */
        r = dns_name_from_wire_format(&data, &data_len, &name);
        if (r < 0) {
                if (FLAGS_SET(option[0], DHCP_FQDN_FLAG_E))
                        return -EBADMSG;

                /* Wire format failed, try ASCII format */
                r = dhcp_option_parse_string(option + 3, len - 3, &name);
                if (r < 0)
                        return r;
        }

        if (!name) {
                *fqdn = mfree(*fqdn);
                return 0;
        }

        r = dns_name_normalize(name, 0, &normalized);
        if (r < 0)
                return r;

        if (is_localhost(normalized))
                return -EINVAL;

        if (dns_name_is_root(normalized))
                return -EINVAL;

        return free_and_replace(*fqdn, normalized);
}

static int lease_parse_captive_portal(const uint8_t *option, size_t len, char **uri) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(option);
        assert(uri);

        r = dhcp_option_parse_string(option, len, &s);
        if (r < 0)
                return r;
        if (s && !in_charset(s, URI_VALID))
                return -EINVAL;

        return free_and_replace(*uri, s);
}

static int lease_parse_in_addrs(const uint8_t *option, size_t len, struct in_addr **addresses, size_t *n_addresses) {
        assert(option || len == 0);
        assert(addresses);
        assert(n_addresses);

        if (len <= 0) {
                *n_addresses = 0;
                *addresses = mfree(*addresses);
                return 0;
        }

        if (len % 4 != 0)
                return -EINVAL;

        size_t n = len / 4;
        struct in_addr *a = newdup(struct in_addr, option, n);
        if (!a)
                return -ENOMEM;

        *n_addresses = n;
        return free_and_replace(*addresses, a);
}

static int lease_parse_sip_server(const uint8_t *option, size_t len, struct in_addr **sips, size_t *n_sips) {
        assert(option || len == 0);
        assert(sips);
        assert(n_sips);

        if (len <= 0)
                return -EINVAL;

        /* The SIP record is like the other, regular server records, but prefixed with a single "encoding"
         * byte that is either 0 or 1. We only support it to be 1 for now. Let's drop it and parse it like
         * the other fields */

        if (option[0] != 1) { /* We only support IP address encoding for now */
                *sips = mfree(*sips);
                *n_sips = 0;
                return 0;
        }

        return lease_parse_in_addrs(option + 1, len - 1, sips, n_sips);
}

static int lease_parse_dns_name(const uint8_t *optval, size_t optlen, char **ret) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(optval);
        assert(ret);

        r = dns_name_from_wire_format(&optval, &optlen, &name);
        if (r < 0)
                return r;
        if (r == 0 || optlen != 0)
                return -EBADMSG;

        *ret = TAKE_PTR(name);
        return r;
}

static int lease_parse_dnr(const uint8_t *option, size_t len, sd_dns_resolver **dnr, size_t *n_dnr) {
        int r;
        sd_dns_resolver *res_list = NULL;
        size_t n_resolvers = 0;
        CLEANUP_ARRAY(res_list, n_resolvers, dns_resolver_done_many);

        assert(option || len == 0);
        assert(dnr);
        assert(n_dnr);

        _cleanup_(sd_dns_resolver_done) sd_dns_resolver res = {};

        size_t offset = 0;
        while (offset < len) {
                /* Instance Data length */
                if (offset + 2 > len)
                        return -EBADMSG;
                size_t ilen = unaligned_read_be16(option + offset);
                if (offset + ilen + 2 > len)
                        return -EBADMSG;
                offset += 2;
                size_t iend = offset + ilen;

                /* priority */
                if (offset + 2 > len)
                        return -EBADMSG;
                res.priority = unaligned_read_be16(option + offset);
                offset += 2;

                /* Authenticated Domain Name */
                if (offset + 1 > len)
                        return -EBADMSG;
                ilen = option[offset++];
                if (offset + ilen > iend)
                        return -EBADMSG;

                r = lease_parse_dns_name(option + offset, ilen, &res.auth_name);
                if (r < 0)
                        return r;
                r = dns_name_is_valid_ldh(res.auth_name);
                if (r < 0)
                        return r;
                if (!r)
                        return -EBADMSG;
                if (dns_name_is_root(res.auth_name))
                        return -EBADMSG;
                offset += ilen;

                /* RFC9463 § 3.1.6: In ADN-only mode, server omits everything after the ADN.
                 * We don't support these, but they are not invalid. */
                if (offset == iend) {
                        log_debug("Received ADN-only DNRv4 option, ignoring.");
                        sd_dns_resolver_done(&res);
                        continue;
                }

                /* IPv4 addrs */
                if (offset + 1 > len)
                        return -EBADMSG;
                ilen = option[offset++];
                if (offset + ilen > iend)
                        return -EBADMSG;

                size_t n_addrs;
                _cleanup_free_ struct in_addr *addrs = NULL;
                r = lease_parse_in_addrs(option + offset, ilen, &addrs, &n_addrs);
                if (r < 0)
                        return r;
                offset += ilen;

                /* RFC9463 § 3.1.8: option MUST include at least one valid IP addr */
                if (!n_addrs)
                        return -EBADMSG;

                res.addrs = new(union in_addr_union, n_addrs);
                if (!res.addrs)
                        return -ENOMEM;
                for (size_t i = 0; i < n_addrs; i++) {
                        union in_addr_union addr = {.in = addrs[i]};
                        /* RFC9463 § 5.2 client MUST discard multicast and host loopback addresses */
                        if (in_addr_is_multicast(AF_INET, &addr) ||
                            in_addr_is_localhost(AF_INET, &addr))
                                return -EBADMSG;
                        res.addrs[i] = addr;
                }
                res.n_addrs = n_addrs;
                res.family = AF_INET;

                /* service params */
                r = dnr_parse_svc_params(option + offset, iend-offset, &res);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* We can't use this record, but it was not invalid. */
                        log_debug("Received DNRv4 option with unsupported SvcParams, ignoring.");
                        sd_dns_resolver_done(&res);
                        continue;
                }
                offset = iend;

                /* Append the latest resolver */
                if (!GREEDY_REALLOC0(res_list, n_resolvers+1))
                        return -ENOMEM;

                res_list[n_resolvers++] = TAKE_STRUCT(res);
        }

        typesafe_qsort(res_list, n_resolvers, dns_resolver_prio_compare);

        dns_resolver_done_many(*dnr, *n_dnr);
        *dnr = TAKE_PTR(res_list);
        *n_dnr = n_resolvers;

        return n_resolvers;
}

static int lease_parse_static_routes(sd_dhcp_lease *lease, const uint8_t *option, size_t len) {
        int r;

        assert(lease);
        assert(option || len <= 0);

        if (len % 8 != 0)
                return -EINVAL;

        while (len >= 8) {
                struct in_addr dst, gw;
                uint8_t prefixlen;

                assert_se(lease_parse_be32(option, 4, &dst.s_addr) >= 0);
                option += 4;

                assert_se(lease_parse_be32(option, 4, &gw.s_addr) >= 0);
                option += 4;

                len -= 8;

                r = in4_addr_default_prefixlen(&dst, &prefixlen);
                if (r < 0) {
                        log_debug("sd-dhcp-lease: cannot determine class of received static route, ignoring.");
                        continue;
                }

                (void) in4_addr_mask(&dst, prefixlen);

                if (!GREEDY_REALLOC(lease->static_routes, lease->n_static_routes + 1))
                        return -ENOMEM;

                lease->static_routes[lease->n_static_routes++] = (struct sd_dhcp_route) {
                        .dst_addr = dst,
                        .gw_addr = gw,
                        .dst_prefixlen = prefixlen,
                };
        }

        return 0;
}

/* parses RFC3442 Classless Static Route Option */
static int lease_parse_classless_routes(sd_dhcp_lease *lease, const uint8_t *option, size_t len) {
        assert(lease);
        assert(option || len <= 0);

        /* option format: (subnet-mask-width significant-subnet-octets gateway-ip) */

        while (len > 0) {
                uint8_t prefixlen, dst_octets;
                struct in_addr dst = {}, gw;

                prefixlen = *option;
                option++;
                len--;

                dst_octets = DIV_ROUND_UP(prefixlen, 8);

                /* can't have more than 4 octets in IPv4 */
                if (dst_octets > 4 || len < dst_octets)
                        return -EINVAL;

                memcpy(&dst, option, dst_octets);
                option += dst_octets;
                len -= dst_octets;

                if (len < 4)
                        return -EINVAL;

                assert_se(lease_parse_be32(option, 4, &gw.s_addr) >= 0);
                option += 4;
                len -= 4;

                if (!GREEDY_REALLOC(lease->classless_routes, lease->n_classless_routes + 1))
                        return -ENOMEM;

                lease->classless_routes[lease->n_classless_routes++] = (struct sd_dhcp_route) {
                        .dst_addr = dst,
                        .gw_addr = gw,
                        .dst_prefixlen = prefixlen,
                };
        }

        return 0;
}

static int lease_parse_6rd(sd_dhcp_lease *lease, const uint8_t *option, size_t len) {
        uint8_t ipv4masklen, prefixlen;
        struct in6_addr prefix;
        _cleanup_free_ struct in_addr *br_addresses = NULL;
        size_t n_br_addresses;

        assert(lease);
        assert(option);

        /* See RFC 5969 Section 7.1.1 */

        if (lease->sixrd_n_br_addresses > 0)
                /* Multiple 6rd option?? */
                return -EINVAL;

        /* option-length: The length of the DHCP option in octets (22 octets with one BR IPv4 address). */
        if (len < 2 + sizeof(struct in6_addr) + sizeof(struct in_addr) ||
            (len - 2 - sizeof(struct in6_addr)) % sizeof(struct in_addr) != 0)
                return -EINVAL;

        /* IPv4MaskLen: The number of high-order bits that are identical across all CE IPv4 addresses
         *              within a given 6rd domain. This may be any value between 0 and 32. Any value
         *              greater than 32 is invalid. */
        ipv4masklen = option[0];
        if (ipv4masklen > 32)
                return -EINVAL;

        /* 6rdPrefixLen: The IPv6 prefix length of the SP's 6rd IPv6 prefix in number of bits. For the
         *               purpose of bounds checking by DHCP option processing, the sum of
         *               (32 - IPv4MaskLen) + 6rdPrefixLen MUST be less than or equal to 128. */
        prefixlen = option[1];
        if (32 - ipv4masklen + prefixlen > 128)
                return -EINVAL;

        /* 6rdPrefix: The service provider's 6rd IPv6 prefix represented as a 16-octet IPv6 address.
         *            The bits in the prefix after the 6rdPrefixlen number of bits are reserved and
         *            MUST be initialized to zero by the sender and ignored by the receiver. */
        memcpy(&prefix, option + 2, sizeof(struct in6_addr));
        (void) in6_addr_mask(&prefix, prefixlen);

        /* 6rdBRIPv4Address: One or more IPv4 addresses of the 6rd Border Relays for a given 6rd domain. */
        n_br_addresses = (len - 2 - sizeof(struct in6_addr)) / sizeof(struct in_addr);
        br_addresses = newdup(struct in_addr, option + 2 + sizeof(struct in6_addr), n_br_addresses);
        if (!br_addresses)
                return -ENOMEM;

        lease->sixrd_ipv4masklen = ipv4masklen;
        lease->sixrd_prefixlen = prefixlen;
        lease->sixrd_prefix = prefix;
        lease->sixrd_br_addresses = TAKE_PTR(br_addresses);
        lease->sixrd_n_br_addresses = n_br_addresses;

        return 0;
}

int dhcp_lease_parse_options(uint8_t code, uint8_t len, const void *option, void *userdata) {
        sd_dhcp_lease *lease = ASSERT_PTR(userdata);
        int r;

        switch (code) {

        case SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity= */ true, &lease->lifetime);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse lease time, ignoring: %m");

                break;

        case SD_DHCP_OPTION_SERVER_IDENTIFIER:
                r = lease_parse_be32(option, len, &lease->server_address);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse server identifier, ignoring: %m");

                break;

        case SD_DHCP_OPTION_SUBNET_MASK:
                r = lease_parse_be32(option, len, &lease->subnet_mask);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse subnet mask, ignoring: %m");
                else
                        lease->have_subnet_mask = true;
                break;

        case SD_DHCP_OPTION_BROADCAST:
                r = lease_parse_be32(option, len, &lease->broadcast);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse broadcast address, ignoring: %m");
                else
                        lease->have_broadcast = true;
                break;

        case SD_DHCP_OPTION_ROUTER:
                r = lease_parse_in_addrs(option, len, &lease->router, &lease->router_size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse router addresses, ignoring: %m");
                break;

        case SD_DHCP_OPTION_RAPID_COMMIT:
                if (len > 0)
                        log_debug("Invalid DHCP Rapid Commit option, ignoring.");
                lease->rapid_commit = true;
                break;

        case SD_DHCP_OPTION_DOMAIN_NAME_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->servers[SD_DHCP_LEASE_DNS].addr, &lease->servers[SD_DHCP_LEASE_DNS].size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse DNS server, ignoring: %m");
                break;

        case SD_DHCP_OPTION_NTP_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->servers[SD_DHCP_LEASE_NTP].addr, &lease->servers[SD_DHCP_LEASE_NTP].size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse NTP server, ignoring: %m");
                break;

        case SD_DHCP_OPTION_SIP_SERVER:
                r = lease_parse_sip_server(option, len, &lease->servers[SD_DHCP_LEASE_SIP].addr, &lease->servers[SD_DHCP_LEASE_SIP].size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse SIP server, ignoring: %m");
                break;

        case SD_DHCP_OPTION_POP3_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->servers[SD_DHCP_LEASE_POP3].addr, &lease->servers[SD_DHCP_LEASE_POP3].size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse POP3 server, ignoring: %m");
                break;

        case SD_DHCP_OPTION_SMTP_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->servers[SD_DHCP_LEASE_SMTP].addr, &lease->servers[SD_DHCP_LEASE_SMTP].size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse SMTP server, ignoring: %m");
                break;

        case SD_DHCP_OPTION_LPR_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->servers[SD_DHCP_LEASE_LPR].addr, &lease->servers[SD_DHCP_LEASE_LPR].size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse LPR server, ignoring: %m");
                break;

        case SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL:
                r = lease_parse_captive_portal(option, len, &lease->captive_portal);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse captive portal, ignoring: %m");
                break;

        case SD_DHCP_OPTION_STATIC_ROUTE:
                r = lease_parse_static_routes(lease, option, len);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse static routes, ignoring: %m");
                break;

        case SD_DHCP_OPTION_MTU_INTERFACE:
                r = lease_parse_u16(option, len, &lease->mtu, 68);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse MTU, ignoring: %m");
                if (lease->mtu < DHCP_MIN_PACKET_SIZE) {
                        log_debug("MTU value of %" PRIu16 " too small. Using default MTU value of %d instead.", lease->mtu, DHCP_MIN_PACKET_SIZE);
                        lease->mtu = DHCP_MIN_PACKET_SIZE;
                }

                break;

        case SD_DHCP_OPTION_DOMAIN_NAME:
                r = lease_parse_domain(option, len, &lease->domainname);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse domain name, ignoring: %m");
                        return 0;
                }

                break;

        case SD_DHCP_OPTION_DOMAIN_SEARCH:
                r = dhcp_lease_parse_search_domains(option, len, &lease->search_domains);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse Domain Search List, ignoring: %m");
                break;

        case SD_DHCP_OPTION_HOST_NAME:
                r = lease_parse_domain(option, len, &lease->hostname);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse hostname, ignoring: %m");
                        return 0;
                }

                break;

        case SD_DHCP_OPTION_FQDN:
                r = lease_parse_fqdn(option, len, &lease->fqdn);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse FQDN, ignoring: %m");
                        return 0;
                }

                break;

        case SD_DHCP_OPTION_ROOT_PATH: {
                _cleanup_free_ char *p = NULL;

                r = dhcp_option_parse_string(option, len, &p);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse root path, ignoring: %m");

                free_and_replace(lease->root_path, p);
                break;
        }
        case SD_DHCP_OPTION_RENEWAL_TIME:
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity= */ true, &lease->t1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T1 time, ignoring: %m");
                break;

        case SD_DHCP_OPTION_REBINDING_TIME:
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity= */ true, &lease->t2);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T2 time, ignoring: %m");
                break;

        case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
                r = lease_parse_classless_routes(lease, option, len);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse classless routes, ignoring: %m");
                break;

        case SD_DHCP_OPTION_TZDB_TIMEZONE: {
                _cleanup_free_ char *tz = NULL;

                r = dhcp_option_parse_string(option, len, &tz);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse timezone option, ignoring: %m");
                        return 0;
                }

                if (!timezone_is_valid(tz, LOG_DEBUG)) {
                        log_debug("Timezone is not valid, ignoring.");
                        return 0;
                }

                free_and_replace(lease->timezone, tz);

                break;
        }

        case SD_DHCP_OPTION_V4_DNR:
                r = lease_parse_dnr(option, len, &lease->dnr, &lease->n_dnr);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse network-designated resolvers, ignoring: %m");
                        return 0;
                }

                break;

        case SD_DHCP_OPTION_VENDOR_SPECIFIC:

                if (len <= 0)
                        lease->vendor_specific = mfree(lease->vendor_specific);
                else {
                        void *p;

                        p = memdup(option, len);
                        if (!p)
                                return -ENOMEM;

                        free_and_replace(lease->vendor_specific, p);
                }

                lease->vendor_specific_len = len;
                break;

        case SD_DHCP_OPTION_6RD:
                r = lease_parse_6rd(lease, option, len);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse 6rd option, ignoring: %m");
                break;

        case SD_DHCP_OPTION_IPV6_ONLY_PREFERRED:
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity= */ false, &lease->ipv6_only_preferred_usec);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse IPv6 only preferred option, ignoring: %m");

                else if (lease->ipv6_only_preferred_usec < MIN_V6ONLY_WAIT_USEC &&
                         !network_test_mode_enabled())
                        lease->ipv6_only_preferred_usec = MIN_V6ONLY_WAIT_USEC;
                break;

        case SD_DHCP_OPTION_PRIVATE_BASE ... SD_DHCP_OPTION_PRIVATE_LAST:
                r = dhcp_lease_insert_private_option(lease, code, option, len);
                if (r < 0)
                        return r;

                break;

        default:
                log_debug("Ignoring DHCP option %"PRIu8" while parsing.", code);
        }

        return 0;
}

/* Parses compressed domain names. */
int dhcp_lease_parse_search_domains(const uint8_t *option, size_t len, char ***domains) {
        _cleanup_strv_free_ char **names = NULL;
        size_t pos = 0, cnt = 0;
        int r;

        assert(domains);
        assert(option || len == 0);

        if (len == 0)
                return -EBADMSG;

        while (pos < len) {
                _cleanup_free_ char *name = NULL;
                size_t n = 0;
                size_t jump_barrier = pos, next_chunk = 0;
                bool first = true;

                for (;;) {
                        uint8_t c;
                        c = option[pos++];

                        if (c == 0) {
                                /* End of name */
                                break;
                        } else if (c <= 63) {
                                const char *label;

                                /* Literal label */
                                label = (const char*) (option + pos);
                                pos += c;
                                if (pos >= len)
                                        return -EBADMSG;

                                if (!GREEDY_REALLOC(name, n + !first + DNS_LABEL_ESCAPED_MAX))
                                        return -ENOMEM;

                                if (first)
                                        first = false;
                                else
                                        name[n++] = '.';

                                r = dns_label_escape(label, c, name + n, DNS_LABEL_ESCAPED_MAX);
                                if (r < 0)
                                        return r;

                                n += r;
                        } else if (FLAGS_SET(c, 0xc0)) {
                                /* Pointer */

                                uint8_t d;
                                uint16_t ptr;

                                if (pos >= len)
                                        return -EBADMSG;

                                d = option[pos++];
                                ptr = (uint16_t) (c & ~0xc0) << 8 | (uint16_t) d;

                                /* Jumps are limited to a "prior occurrence" (RFC-1035 4.1.4) */
                                if (ptr >= jump_barrier)
                                        return -EBADMSG;
                                jump_barrier = ptr;

                                /* Save current location so we don't end up re-parsing what's parsed so far. */
                                if (next_chunk == 0)
                                        next_chunk = pos;

                                pos = ptr;
                        } else
                                return -EBADMSG;
                }

                if (!GREEDY_REALLOC(name, n + 1))
                        return -ENOMEM;
                name[n] = 0;

                r = strv_extend(&names, name);
                if (r < 0)
                        return r;

                cnt++;

                if (next_chunk != 0)
                      pos = next_chunk;
        }

        strv_free_and_replace(*domains, names);

        return cnt;
}

int dhcp_lease_insert_private_option(sd_dhcp_lease *lease, uint8_t tag, const void *data, uint8_t len) {
        struct sd_dhcp_raw_option *option, *before = NULL;

        assert(lease);

        LIST_FOREACH(options, cur, lease->private_options) {
                if (tag < cur->tag) {
                        before = cur;
                        break;
                }
                if (tag == cur->tag) {
                        log_debug("Ignoring duplicate option, tagged %i.", tag);
                        return 0;
                }
        }

        option = new(struct sd_dhcp_raw_option, 1);
        if (!option)
                return -ENOMEM;

        option->tag = tag;
        option->length = len;
        option->data = memdup(data, len);
        if (!option->data) {
                free(option);
                return -ENOMEM;
        }

        LIST_INSERT_BEFORE(options, lease->private_options, before, option);
        return 0;
}

int dhcp_lease_new(sd_dhcp_lease **ret) {
        sd_dhcp_lease *lease;

        lease = new0(sd_dhcp_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->n_ref = 1;

        *ret = lease;
        return 0;
}

static int lease_routes_append_json(sd_dhcp_route **routes, const char *key, size_t n_routes, sd_json_variant **v){
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        FOREACH_ARRAY(route, routes, n_routes) {
                r = sd_json_variant_append_arraybo(
                                &array,
                                JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING("Destination", &(*route)->dst_addr),
                                JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING_NON_NULL("Gateway", &(*route)->gw_addr),
                                SD_JSON_BUILD_PAIR_UNSIGNED("DestinationPrefixLength", (*route)->dst_prefixlen));
                if (r < 0)
                        return r;
        }

        return sd_json_variant_merge_objectbo(v, SD_JSON_BUILD_PAIR_VARIANT(key, array));
}

static int dhcp_lease_append_json(sd_dhcp_lease *lease, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ sd_dhcp_route **routes = NULL;
        const struct in_addr *addresses;
        struct in_addr address;
        const void *data;
        size_t data_len;
        const char *string;
        uint16_t mtu;
        char **search_domains;
        usec_t t;
        int count;
        int r;

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING_NON_NULL("Address", &address));
                if (r < 0)
                        log_debug("Failed to add address field to Json lease: %s", strerror(-r));
        }
        r = sd_dhcp_lease_get_netmask(lease, &address);
        if (r >= 0)
                r = sd_json_variant_merge_objectbo(&v, JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING_NON_NULL("Netmask", &address));

        r = sd_dhcp_lease_get_router(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count) {
                        r = sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                        if (r < 0) {
                                log_debug("Failed to add a router address to lease: %s", strerror(-r));
                                break;
                        }
                }
                r = sd_json_variant_set_field(&v, "Router", array);
                if (r < 0)
                        log_debug("Failed to add router field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_server_identifier(lease, &address);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, JSON_BUILD_PAIR_IN4_ADDR("Server_Address", &address));
                if (r < 0)
                        log_debug("Failed to add server_address field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_next_server(lease, &address);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, JSON_BUILD_PAIR_IN4_ADDR("Next_Server", &address));
                if (r < 0)
                        log_debug("Failed to add field next_server to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_broadcast(lease, &address);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, JSON_BUILD_PAIR_IN4_ADDR("Broadcast", &address));
                if (r < 0)
                        log_debug("Failed to add broadcast field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_mtu(lease, &mtu);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_UNSIGNED("MTU", mtu));
                if (r < 0)
                        log_debug("Failed to add mtu field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_t1(lease, &t);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("T1", FORMAT_TIMESPAN(t, USEC_PER_SEC)));
                if (r < 0)
                        log_debug("Failed to add t1 field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_t2(lease, &t);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("T2", FORMAT_TIMESPAN(t, USEC_PER_SEC)));
                if (r < 0)
                        log_debug("Failed to add t2 field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_lifetime(lease, &t);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("Lifetime", FORMAT_TIMESPAN(t, USEC_PER_SEC)));
                if (r < 0)
                        log_debug("Failed to add lifetime field to Json lease: %s", strerror(-r));
       }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *servers = NULL;
        r = sd_dhcp_lease_get_dns(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count)
                      sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                r = sd_json_variant_merge_objectbo(&servers, SD_JSON_BUILD_PAIR_VARIANT("DNS", array));
                if (r < 0)
                        log_debug("Failed to add DNS servers field to Json lease: %s", strerror(-r));

        }

        r = sd_dhcp_lease_get_ntp(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count)
                        sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                r = sd_json_variant_merge_objectbo(&servers, SD_JSON_BUILD_PAIR_VARIANT("NTP", array));
                if (r < 0)
                        log_debug("Failed to add NTP servers field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_sip(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count)
                        sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                r = sd_json_variant_merge_objectbo(&servers, SD_JSON_BUILD_PAIR_VARIANT("SIP", array));
                if (r < 0)
                        log_debug("Failed to add SIP servers field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_pop3(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count)
                         sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                r = sd_json_variant_merge_objectbo(&servers, SD_JSON_BUILD_PAIR_VARIANT("POP3", array));
                if (r < 0)
                        log_debug("Failed to add POP3 servers field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_smtp(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count)
                        sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                r = sd_json_variant_merge_objectbo(&servers, SD_JSON_BUILD_PAIR_VARIANT("SMTP", array));
                if (r < 0)
                        log_debug("Failed to add SMTP servers field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_lpr(lease, &addresses);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;
                FOREACH_ARRAY(addr, addresses, count)
                        sd_json_variant_append_arrayb(&array, JSON_BUILD_IN4_ADDR(addr));
                r = sd_json_variant_merge_objectbo(&servers, SD_JSON_BUILD_PAIR_VARIANT("LPR", array));
                if (r < 0)
                        log_debug("Failed to add LPR servers field to Json lease: %s", strerror(-r));
        }

        if(servers) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_VARIANT("Servers", servers));
                if (r < 0)
                        log_debug("Failed to add servers array to Json lease: %s", strerror(-r));
       }

        sd_dns_resolver *resolvers;
        r = sd_dhcp_lease_get_dnr(lease, &resolvers);
        if (r > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
                count = r;

                FOREACH_ARRAY(res, resolvers, count) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *addrs_array = NULL;
                        _cleanup_strv_free_ char **transports = NULL;

                        FOREACH_ARRAY(addr, res->addrs, res->n_addrs) {
                                r = sd_json_variant_append_arrayb(
                                                &addrs_array,
                                                JSON_BUILD_IN_ADDR(res->family, addr));
                                if (r < 0) {
                                        log_debug("Failed to add a resolver address: %s", strerror(-r));
                                        break;
                                }
                        }

                        r = dns_resolver_transports_to_strv(res->transports, &transports);
                        if (r < 0) {
                                log_debug("Failed to add a resolver transport type to Json lease: %s", strerror(-r));
                                continue;
                        }

                        r = sd_json_variant_append_arrayb(
                                        &array,
                                        SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_UNSIGNED("Priority", res->priority),
                                                        JSON_BUILD_PAIR_VARIANT_NON_NULL("Addresses", addrs_array),
                                                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Port", res->port),
                                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ServerName", res->auth_name),
                                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("DoHPath", res->dohpath),
                                                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Transports", transports)));
                        if (r < 0) {
                                log_debug("Failed to add resolver to Json Lease: %s", strerror(-r));
                                continue;
                        }
                }

                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_VARIANT("DNR", array));
                if (r < 0) {
                         log_debug("Failed to add DNR field to Json lease: %s", strerror(-r));
                }
        }

        r = sd_dhcp_lease_get_domainname(lease, &string);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("Domain_Name", string));
                if (r < 0)
                        log_debug("Failed to add Domain_name field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_search_domains(lease, &search_domains);
        if (r > 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRV("Domain_Search_List", search_domains));
                if (r < 0)
                        log_debug("Failed to add domain_search_list field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_hostname(lease, &string);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("Hostname", string));
                if (r < 0)
                        log_debug("Failed to add hostname field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_root_path(lease, &string);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("Root_Path", string));
                if (r < 0)
                        log_debug("Failed to add root_path field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_static_routes(lease, &routes);
        if (r > 0) {
                r = lease_routes_append_json(routes, "Static_Routes", r, &v);
                if (r < 0)
                        log_debug("Failed to add static_routes field to Json lease: %s", strerror(-r));
        }
        routes = mfree(routes);

        r = sd_dhcp_lease_get_classless_routes(lease, &routes);
        if (r > 0) {
                r = lease_routes_append_json(routes, "Classless_Routes", r, &v);
                if (r < 0)
                        log_debug("Failed to add classless_routes field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_timezone(lease, &string);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("Timezone", string));
                if (r < 0)
                        log_debug("Failed to add timezone field to Json lease: %s", strerror(-r));
        }

        if (sd_dhcp_client_id_is_set(&lease->client_id)) {
                r = sd_json_variant_merge_objectbo(&v,
                                                   SD_JSON_BUILD_PAIR_BYTE_ARRAY("Client_Id", lease->client_id.raw, lease->client_id.size));
                if (r < 0)
                        log_debug("Failed to add client_id field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_timestamp(lease, CLOCK_REALTIME, &t);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_STRING("Timestamp_realtime", FORMAT_TIMESTAMP_STYLE(t, TIMESTAMP_US)));
                if (r < 0)
                        log_debug("Failed to add timestamp_realtime field to Json lease: %s", strerror(-r));
        }

        r = sd_dhcp_lease_get_vendor_specific(lease, &data, &data_len);
        if (r >= 0) {
                r = sd_json_variant_merge_objectbo(&v, SD_JSON_BUILD_PAIR_HEX("Vendor_Specific", data, data_len));
                if (r < 0)
                        log_debug("Failed to add vendor_specific field to Json lease: %s", strerror(-r));
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *private_options_array = NULL;
        LIST_FOREACH(options, option, lease->private_options) {

                r = sd_json_variant_append_arraybo(
                                &private_options_array,
                                SD_JSON_BUILD_PAIR_UNSIGNED("Option", option->tag),
                                SD_JSON_BUILD_PAIR_HEX("Data", option->data, option->length));
                if (r < 0) {
                        log_debug("Failed to add a private option to Json lease: %s", strerror(-r));
                        continue;
                }
        }
        r = json_variant_set_field_non_null(&v, "Private_Options", private_options_array);
        if (r < 0)
                log_debug("Failed to add Private_Options field to Json lease: %s", strerror(-r));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *requested_options_array = NULL;
        LIST_FOREACH(options, opt, lease->requested_options_data) {
                r = sd_json_variant_append_arraybo(
                                &requested_options_array,
                                SD_JSON_BUILD_PAIR_UNSIGNED("Option", opt->tag),
                                SD_JSON_BUILD_PAIR_STRING("Data", opt->data));
                if (r < 0)
                        log_debug("Failed to add a requested option to Json lease: %s", strerror(-r));
        }
        r = json_variant_set_field_non_null(&v, "Requested_Options", requested_options_array);
        if (r < 0)
                log_debug("Failed to add Requested_Options field to Json lease: %s", strerror(-r));

        if (!v)
                return -ENODATA;

        *ret = TAKE_PTR(v);
        return 0;
}

int dhcp_lease_save(sd_dhcp_lease *lease, int dir_fd, const char *lease_file) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(lease);
        assert(lease_file);
        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);


        r = dhcp_lease_append_json(lease, &v);

        if (r < 0)
                return r;

        r = fopen_temporary_at(dir_fd, lease_file, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        r = sd_json_variant_dump(v, SD_JSON_FORMAT_FLUSH | SD_JSON_FORMAT_PRETTY_AUTO, f, /* prefix= */ NULL);
        if (r < 0)
                return r;

        r = conservative_renameat(dir_fd, temp_path, dir_fd, lease_file);
        if (r < 0)
                return r;

        temp_path = mfree(temp_path);

        return 0;
}

static char **private_options_free(char **options) {
        if (!options)
                return NULL;

        free_many_charp(options, SD_DHCP_OPTION_PRIVATE_LAST - SD_DHCP_OPTION_PRIVATE_BASE + 1);

        return mfree(options);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(char**, private_options_free);

/* Dispatcher for an array of objects, pass in single element dispatcher */
static int json_dispatch_array_generic(const char *name,
                                       sd_json_variant *variant,
                                       sd_json_dispatch_flags_t flags,
                                       void *userdata,
                                       size_t element_size,
                                       int (*dispatch_element)(const char *, sd_json_variant *, sd_json_dispatch_flags_t, void *)) {

        void **array_ptr = ASSERT_PTR(userdata);
        _cleanup_free_ void *array = NULL;
        size_t count = 0;
        int r;

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        count = sd_json_variant_elements(variant);
        if (count > SIZE_MAX / element_size)
                return json_log_oom(variant, flags);

        /* Allocate space for all elements */
        array = malloc0(count * element_size);
        if (!array)
                return json_log_oom(variant, flags);

        /* Iterate through outer array and dispatch each element */
        sd_json_variant *element;
        size_t i = 0;
        JSON_VARIANT_ARRAY_FOREACH(element, variant) {
                r = dispatch_element(name, element, flags, (uint8_t*)array + (i * element_size));
                if (r < 0)
                        return r;
                i++;
        }

        free(*array_ptr);
        *array_ptr = TAKE_PTR(array);
        return 0;
}

static int json_dispatch_in_addr_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        return json_dispatch_array_generic(name, variant, flags, userdata, sizeof(struct in_addr), json_dispatch_in_addr);
}

static int json_dispatch_servers_object(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_dhcp_lease *lease = ASSERT_PTR(userdata);
        int r;

        static const sd_json_dispatch_field servers_dispatch_table[] = {
                { "DNS",  SD_JSON_VARIANT_ARRAY,  json_dispatch_in_addr_array,  offsetof(sd_dhcp_lease, servers[SD_DHCP_LEASE_DNS].addr),  0 },
                { "NTP",  SD_JSON_VARIANT_ARRAY,  json_dispatch_in_addr_array,  offsetof(sd_dhcp_lease, servers[SD_DHCP_LEASE_NTP].addr),  0 },
                { "SIP",  SD_JSON_VARIANT_ARRAY,  json_dispatch_in_addr_array,  offsetof(sd_dhcp_lease, servers[SD_DHCP_LEASE_SIP].addr),  0 },
                { "POP3", SD_JSON_VARIANT_ARRAY,  json_dispatch_in_addr_array,  offsetof(sd_dhcp_lease, servers[SD_DHCP_LEASE_POP3].addr), 0 },
                { "SMTP", SD_JSON_VARIANT_ARRAY,  json_dispatch_in_addr_array,  offsetof(sd_dhcp_lease, servers[SD_DHCP_LEASE_SMTP].addr), 0 },
                { "LPR",  SD_JSON_VARIANT_ARRAY,  json_dispatch_in_addr_array,  offsetof(sd_dhcp_lease, servers[SD_DHCP_LEASE_LPR].addr),  0 },
                {}
        };

        r = sd_json_dispatch(variant, servers_dispatch_table, flags, lease);

        if (r < 0)
                return r;

        const char *field_names[] = {"DNS", "NTP", "SIP", "POP3", "SMTP", "LPR"};
        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++) {
                if (lease->servers[i].addr) {
                        sd_json_variant *server_variant = sd_json_variant_by_key(variant, field_names[i]);
                        if (server_variant)
                                lease->servers[i].size = sd_json_variant_elements(server_variant);
                }
        }

        return 0;
}

static int json_dispatch_route(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field route_dispatch_table[] = {
                { "Destination",             SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,  offsetof(struct sd_dhcp_route, dst_addr),      SD_JSON_MANDATORY },
                { "Gateway",                 SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,  offsetof(struct sd_dhcp_route, gw_addr),       SD_JSON_MANDATORY },
                { "DestinationPrefixLength", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8, offsetof(struct sd_dhcp_route, dst_prefixlen), SD_JSON_MANDATORY },
                {}
        };

        return sd_json_dispatch(variant, route_dispatch_table, flags, userdata);
}

static int json_dispatch_routes_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        return json_dispatch_array_generic(name, variant, flags, userdata, sizeof(struct sd_dhcp_route), json_dispatch_route);
}

static int json_dispatch_lease_realtime(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_dhcp_lease *lease = userdata;
        usec_t timestamp_usec;
        triple_timestamp ts = {};
        const char *saved_realtime;
        int r;

        if (sd_json_variant_is_null(variant))
                return 0;

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        saved_realtime = sd_json_variant_string(variant);

        r = parse_timestamp(saved_realtime, &timestamp_usec);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to parse timestamp '%s': %m", saved_realtime);

        triple_timestamp_from_realtime(&ts, timestamp_usec); /* set timestamp from realtime value */
        dhcp_lease_set_timestamp(lease, &ts); /* set timestamp onto lease */

        return 0;
}

static int json_dispatch_vendor_specific(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_dhcp_lease *lease = userdata;
        _cleanup_(iovec_done) struct iovec iov = {};
        int r;

        r = json_dispatch_unhex_iovec(name, variant, flags, &iov);
        if (r < 0)
                return r;

        free(lease->vendor_specific);
        lease->vendor_specific = TAKE_PTR(iov.iov_base);
        lease->vendor_specific_len = iov.iov_len;
        return 0;
}

static int json_dispatch_option(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        struct sd_dhcp_raw_option *option = userdata;
        _cleanup_(iovec_done) struct iovec data_iov = {};
        int r;

        sd_json_variant *tag = sd_json_variant_by_key(variant, "Option");
        sd_json_variant *data = sd_json_variant_by_key(variant, "Data");
        if (!tag || !data)
                return -EINVAL;

        option->tag = (uint8_t) sd_json_variant_unsigned(tag);

        r = json_dispatch_unhex_iovec("Data", data, flags, &data_iov);
        if (r < 0)
                return r;

        /* Set length from iovec */
        option->length = data_iov.iov_len;
        option->data = TAKE_PTR(data_iov.iov_base);

        return 0;
}

static int json_dispatch_private_options(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_dhcp_lease *lease = userdata;
        sd_json_variant *v;
        int r;

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_free_ struct sd_dhcp_raw_option *option = NULL;

                option = new0(struct sd_dhcp_raw_option, 1);
                if (!option)
                        return json_log_oom(variant, flags);

                r = json_dispatch_option(name, v, flags, option);
                if (r < 0)
                        return r;

                r = dhcp_lease_insert_private_option(lease, option->tag, option->data, option->length);
                option->data = mfree(option->data); /* needs free before cleanup_free runs */
                if (r < 0)
                        return r;
        }

        return 0;
}

/* DNR address dispatcher - handles address objects */
static int json_dispatch_dnr_address(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        return json_dispatch_array_generic(name, variant, flags, userdata, sizeof(union in_addr_union), json_dispatch_in_addr);
}

/* Transports doesn't have string_to equivalent */
static int json_dispatch_dnr_transports(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_dns_alpn_flags *transports = userdata;
        sd_json_variant *item;

        *transports = 0;
        JSON_VARIANT_ARRAY_FOREACH(item, variant) {
                const char *s = sd_json_variant_string(item);
                if (!s)
                        return -EINVAL;
                if (streq(s, "h2"))
                        *transports |= SD_DNS_ALPN_HTTP_2_TLS;
                else if (streq(s, "h3"))
                        *transports |= SD_DNS_ALPN_HTTP_3;
                else if (streq(s, "dot"))
                        *transports |= SD_DNS_ALPN_DOT;
                else if (streq(s, "doq"))
                        *transports |= SD_DNS_ALPN_DOQ;
        }
        return 0;
}

/* DNR resolver dispatcher */
static int json_dispatch_one_dnr(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dnr_dispatch_table[] = {
                { "Priority",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,      offsetof(sd_dns_resolver, priority),   0 },
                { "ServerName", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,      offsetof(sd_dns_resolver, auth_name),  0 },
                { "Port",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,      offsetof(sd_dns_resolver, port),       0 },
                { "DoHPath",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,      offsetof(sd_dns_resolver, dohpath),    0 },
                { "Transports", SD_JSON_VARIANT_ARRAY,         json_dispatch_dnr_transports, offsetof(sd_dns_resolver, transports), 0 },
                { "Addresses",  SD_JSON_VARIANT_ARRAY,         json_dispatch_dnr_address,    offsetof(sd_dns_resolver, addrs),      0 },
                {}
        };

        sd_dns_resolver *resolver = userdata;
        int r;

        r = sd_json_dispatch(variant, dnr_dispatch_table, flags, resolver);
        if (r < 0)
                return r;

        /*set for DHCP4 */
        resolver->family = AF_INET;

        return 0;
}

/* DNR array dispatcher */
static int json_dispatch_dnr_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        return json_dispatch_array_generic(name, variant, flags, userdata, sizeof(struct sd_dns_resolver), json_dispatch_one_dnr);
}

static int json_dispatch_timespan(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {

        usec_t *usec = userdata;
        const char *s;

        if (sd_json_variant_is_null(variant))
                return 0;

        s = sd_json_variant_string(variant);
        if (!s)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string", name);

        return parse_sec(s, usec);
}

int dhcp_lease_load(sd_dhcp_lease **ret, const char *lease_file) {
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned line = 0, column = 0;
        int r;

        assert(lease_file);
        assert(ret);

        r = sd_json_parse_file(
                        /* f= */ NULL,
                        lease_file,
                        /* flags= */ SD_JSON_PARSE_MUST_BE_OBJECT,
                        &v,
                        /* reterr_line= */ &line,
                        /* ret_column= */ &column);
        if (r < 0)
                return r;

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        static const sd_json_dispatch_field dispatch_lease_file_table[] = {
                { "Address",            SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,         offsetof(sd_dhcp_lease, address),          SD_JSON_MANDATORY },
                { "Router",             SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr_array,   offsetof(sd_dhcp_lease, router),           SD_JSON_MANDATORY },
                { "Netmask",            SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,         offsetof(sd_dhcp_lease, subnet_mask),      SD_JSON_MANDATORY },
                { "Server_Address",     SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,         offsetof(sd_dhcp_lease, server_address),   SD_JSON_MANDATORY },
                { "Next_Server",        SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,         offsetof(sd_dhcp_lease, next_server),      0                 },
                { "Client_Id",          SD_JSON_VARIANT_ARRAY,         json_dispatch_client_id,       offsetof(sd_dhcp_lease, client_id),        0                 },
                { "Timezone",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(sd_dhcp_lease, timezone),         0                 },
                { "Lifetime",           SD_JSON_VARIANT_STRING,        json_dispatch_timespan,        offsetof(sd_dhcp_lease, lifetime),         0                 },
                { "T1",                 SD_JSON_VARIANT_STRING,        json_dispatch_timespan,        offsetof(sd_dhcp_lease, t1),               0                 },
                { "T2",                 SD_JSON_VARIANT_STRING,        json_dispatch_timespan,        offsetof(sd_dhcp_lease, t2),               0                 },
                { "Timestamp_realtime", SD_JSON_VARIANT_STRING,        json_dispatch_lease_realtime,  0,                                         0                 },
                { "Servers",            SD_JSON_VARIANT_OBJECT,        json_dispatch_servers_object,  0,                                         0                 },
                { "Static_Routes",      SD_JSON_VARIANT_ARRAY,         json_dispatch_routes_array,    offsetof(sd_dhcp_lease, static_routes),    0                 },
                { "Classless_Routes",   SD_JSON_VARIANT_ARRAY,         json_dispatch_routes_array,    offsetof(sd_dhcp_lease, classless_routes), 0                 },
                { "Root_Path",          SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(sd_dhcp_lease, root_path),        0                 },
                { "Broadcast",          SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,         offsetof(sd_dhcp_lease, broadcast),        0                 },
                { "Domain_Name",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(sd_dhcp_lease, domainname),       0                 },
                { "Hostname",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,       offsetof(sd_dhcp_lease, hostname),         0                 },
                { "MTU",                _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,       offsetof(sd_dhcp_lease, mtu),              0                 },
                { "Domain_Search_List", SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(sd_dhcp_lease, search_domains),   0                 },
                { "DNR",                SD_JSON_VARIANT_ARRAY,         json_dispatch_dnr_array,       offsetof(sd_dhcp_lease, dnr),              0                 },
                { "Vendor_Specific",    SD_JSON_VARIANT_STRING,        json_dispatch_vendor_specific, 0,                                         0                 },
                { "Private_Options",    SD_JSON_VARIANT_ARRAY,         json_dispatch_private_options, 0,                                         0                 },
                {}
        };

        r = sd_json_dispatch(v, dispatch_lease_file_table, SD_JSON_ALLOW_EXTENSIONS, lease);
        if (r < 0)
                return r;

        if (lease->router) {
                sd_json_variant *router_variant = sd_json_variant_by_key(v, "Router");
                if (router_variant)
                        lease->router_size = sd_json_variant_elements(router_variant);
        }

        if (lease->subnet_mask) {
                lease->have_subnet_mask = true;
        }

        if (lease->broadcast) {
                lease->have_broadcast = true;
        }

        if (lease->static_routes) {
                sd_json_variant *routes_variant = sd_json_variant_by_key(v, "Static_Routes");
                if (routes_variant)
                        lease->n_static_routes = sd_json_variant_elements(routes_variant);
        }

        if (lease->classless_routes) {
                sd_json_variant *routes_variant = sd_json_variant_by_key(v, "Classless_Routes");
                if (routes_variant)
                        lease->n_classless_routes = sd_json_variant_elements(routes_variant);
        }

        if (lease->dnr) {
                sd_json_variant *dnr_variant = sd_json_variant_by_key(v, "DNR");
                if (dnr_variant)
                        lease->n_dnr = sd_json_variant_elements(dnr_variant);

                /* Set n_addrs for each resolver */
                sd_json_variant *resolver;
                size_t i = 0;
                JSON_VARIANT_ARRAY_FOREACH(resolver, dnr_variant) {
                    sd_json_variant *addrs_variant = sd_json_variant_by_key(resolver, "Addresses");
                    if (addrs_variant)
                        lease->dnr[i].n_addrs = sd_json_variant_elements(addrs_variant);
                    i++;
                }
        }

        *ret = TAKE_PTR(lease);

        return 0;
}

int dhcp_lease_set_default_subnet_mask(sd_dhcp_lease *lease) {
        struct in_addr address, mask;
        int r;

        assert(lease);

        if (lease->have_subnet_mask)
                return 0;

        if (lease->address == 0)
                return -ENODATA;

        address.s_addr = lease->address;

        /* fall back to the default subnet masks based on address class */
        r = in4_addr_default_subnet_mask(&address, &mask);
        if (r < 0)
                return r;

        lease->subnet_mask = mask.s_addr;
        lease->have_subnet_mask = true;

        return 0;
}

int sd_dhcp_lease_get_client_id(sd_dhcp_lease *lease, const sd_dhcp_client_id **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!sd_dhcp_client_id_is_set(&lease->client_id))
                return -ENODATA;

        *ret = &lease->client_id;

        return 0;
}

int dhcp_lease_set_client_id(sd_dhcp_lease *lease, const sd_dhcp_client_id *client_id) {
        assert_return(lease, -EINVAL);

        if (!sd_dhcp_client_id_is_set(client_id))
                return sd_dhcp_client_id_clear(&lease->client_id);

        lease->client_id = *client_id;

        return 0;
}

int sd_dhcp_lease_get_timezone(sd_dhcp_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->timezone)
                return -ENODATA;

        *ret = lease->timezone;
        return 0;
}

int sd_dhcp_route_get_destination(sd_dhcp_route *route, struct in_addr *destination) {
        assert_return(route, -EINVAL);
        assert_return(destination, -EINVAL);

        *destination = route->dst_addr;
        return 0;
}

int sd_dhcp_route_get_destination_prefix_length(sd_dhcp_route *route, uint8_t *length) {
        assert_return(route, -EINVAL);
        assert_return(length, -EINVAL);

        *length = route->dst_prefixlen;
        return 0;
}

int sd_dhcp_route_get_gateway(sd_dhcp_route *route, struct in_addr *gateway) {
        assert_return(route, -EINVAL);
        assert_return(gateway, -EINVAL);

        *gateway = route->gw_addr;
        return 0;
}
