/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-dhcp-lease.h"

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "dhcp-option.h"
#include "dns-domain.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "network-common.h"
#include "network-internal.h"
#include "parse-util.h"
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

        if (!lease->hostname)
                return -ENODATA;

        *hostname = lease->hostname;
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
        free(lease->domainname);
        free(lease->captive_portal);

        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(lease->servers[i].addr);

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

static int lease_parse_domain(const uint8_t *option, size_t len, char **ret) {
        _cleanup_free_ char *name = NULL, *normalized = NULL;
        int r;

        assert(option);
        assert(ret);

        r = dhcp_option_parse_string(option, len, &name);
        if (r < 0)
                return r;
        if (!name) {
                *ret = mfree(*ret);
                return 0;
        }

        r = dns_name_normalize(name, 0, &normalized);
        if (r < 0)
                return r;

        if (is_localhost(normalized))
                return -EINVAL;

        if (dns_name_is_root(normalized))
                return -EINVAL;

        free_and_replace(*ret, normalized);

        return 0;
}

static int lease_parse_captive_portal(const uint8_t *option, size_t len, char **ret) {
        _cleanup_free_ char *uri = NULL;
        int r;

        assert(option);
        assert(ret);

        r = dhcp_option_parse_string(option, len, &uri);
        if (r < 0)
                return r;
        if (uri && !in_charset(uri, URI_VALID))
                return -EINVAL;

        return free_and_replace(*ret, uri);
}

static int lease_parse_in_addrs(const uint8_t *option, size_t len, struct in_addr **ret, size_t *n_ret) {
        assert(option || len == 0);
        assert(ret);
        assert(n_ret);

        if (len <= 0) {
                *ret = mfree(*ret);
                *n_ret = 0;
        } else {
                size_t n_addresses;
                struct in_addr *addresses;

                if (len % 4 != 0)
                        return -EINVAL;

                n_addresses = len / 4;

                addresses = newdup(struct in_addr, option, n_addresses);
                if (!addresses)
                        return -ENOMEM;

                free_and_replace(*ret, addresses);
                *n_ret = n_addresses;
        }

        return 0;
}

static int lease_parse_sip_server(const uint8_t *option, size_t len, struct in_addr **ret, size_t *n_ret) {
        assert(option || len == 0);
        assert(ret);
        assert(n_ret);

        if (len <= 0)
                return -EINVAL;

        /* The SIP record is like the other, regular server records, but prefixed with a single "encoding"
         * byte that is either 0 or 1. We only support it to be 1 for now. Let's drop it and parse it like
         * the other fields */

        if (option[0] != 1) { /* We only support IP address encoding for now */
                *ret = mfree(*ret);
                *n_ret = 0;
                return 0;
        }

        return lease_parse_in_addrs(option + 1, len - 1, ret, n_ret);
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
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity = */ true, &lease->lifetime);
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

        case SD_DHCP_OPTION_ROOT_PATH:
                r = dhcp_option_parse_string(option, len, &lease->root_path);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse root path, ignoring: %m");
                break;

        case SD_DHCP_OPTION_RENEWAL_TIME:
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity = */ true, &lease->t1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T1 time, ignoring: %m");
                break;

        case SD_DHCP_OPTION_REBINDING_TIME:
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity = */ true, &lease->t2);
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
                r = lease_parse_be32_seconds(option, len, /* max_as_infinity = */ false, &lease->ipv6_only_preferred_usec);
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
                break;
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

int dhcp_lease_save(sd_dhcp_lease *lease, const char *lease_file) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct in_addr address;
        const struct in_addr *addresses;
        const void *data;
        size_t data_len;
        const char *string;
        uint16_t mtu;
        _cleanup_free_ sd_dhcp_route **routes = NULL;
        char **search_domains;
        usec_t t;
        int r;

        assert(lease);
        assert(lease_file);

        r = fopen_temporary(lease_file, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n");

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r >= 0)
                fprintf(f, "ADDRESS=%s\n", IN4_ADDR_TO_STRING(&address));

        r = sd_dhcp_lease_get_netmask(lease, &address);
        if (r >= 0)
                fprintf(f, "NETMASK=%s\n", IN4_ADDR_TO_STRING(&address));

        r = sd_dhcp_lease_get_router(lease, &addresses);
        if (r > 0) {
                fputs("ROUTER=", f);
                serialize_in_addrs(f, addresses, r, NULL, NULL);
                fputc('\n', f);
        }

        r = sd_dhcp_lease_get_server_identifier(lease, &address);
        if (r >= 0)
                fprintf(f, "SERVER_ADDRESS=%s\n", IN4_ADDR_TO_STRING(&address));

        r = sd_dhcp_lease_get_next_server(lease, &address);
        if (r >= 0)
                fprintf(f, "NEXT_SERVER=%s\n", IN4_ADDR_TO_STRING(&address));

        r = sd_dhcp_lease_get_broadcast(lease, &address);
        if (r >= 0)
                fprintf(f, "BROADCAST=%s\n", IN4_ADDR_TO_STRING(&address));

        r = sd_dhcp_lease_get_mtu(lease, &mtu);
        if (r >= 0)
                fprintf(f, "MTU=%" PRIu16 "\n", mtu);

        r = sd_dhcp_lease_get_t1(lease, &t);
        if (r >= 0)
                fprintf(f, "T1=%s\n", FORMAT_TIMESPAN(t, USEC_PER_SEC));

        r = sd_dhcp_lease_get_t2(lease, &t);
        if (r >= 0)
                fprintf(f, "T2=%s\n", FORMAT_TIMESPAN(t, USEC_PER_SEC));

        r = sd_dhcp_lease_get_lifetime(lease, &t);
        if (r >= 0)
                fprintf(f, "LIFETIME=%s\n", FORMAT_TIMESPAN(t, USEC_PER_SEC));

        r = sd_dhcp_lease_get_dns(lease, &addresses);
        if (r > 0) {
                fputs("DNS=", f);
                serialize_in_addrs(f, addresses, r, NULL, NULL);
                fputc('\n', f);
        }

        r = sd_dhcp_lease_get_ntp(lease, &addresses);
        if (r > 0) {
                fputs("NTP=", f);
                serialize_in_addrs(f, addresses, r, NULL, NULL);
                fputc('\n', f);
        }

        r = sd_dhcp_lease_get_sip(lease, &addresses);
        if (r > 0) {
                fputs("SIP=", f);
                serialize_in_addrs(f, addresses, r, NULL, NULL);
                fputc('\n', f);
        }

        r = sd_dhcp_lease_get_domainname(lease, &string);
        if (r >= 0)
                fprintf(f, "DOMAINNAME=%s\n", string);

        r = sd_dhcp_lease_get_search_domains(lease, &search_domains);
        if (r > 0) {
                fputs("DOMAIN_SEARCH_LIST=", f);
                fputstrv(f, search_domains, NULL, NULL);
                fputc('\n', f);
        }

        r = sd_dhcp_lease_get_hostname(lease, &string);
        if (r >= 0)
                fprintf(f, "HOSTNAME=%s\n", string);

        r = sd_dhcp_lease_get_root_path(lease, &string);
        if (r >= 0)
                fprintf(f, "ROOT_PATH=%s\n", string);

        r = sd_dhcp_lease_get_static_routes(lease, &routes);
        if (r > 0)
                serialize_dhcp_routes(f, "STATIC_ROUTES", routes, r);

        routes = mfree(routes);
        r = sd_dhcp_lease_get_classless_routes(lease, &routes);
        if (r > 0)
                serialize_dhcp_routes(f, "CLASSLESS_ROUTES", routes, r);

        r = sd_dhcp_lease_get_timezone(lease, &string);
        if (r >= 0)
                fprintf(f, "TIMEZONE=%s\n", string);

        if (sd_dhcp_client_id_is_set(&lease->client_id)) {
                _cleanup_free_ char *client_id_hex = NULL;

                client_id_hex = hexmem(lease->client_id.raw, lease->client_id.size);
                if (!client_id_hex)
                        return -ENOMEM;
                fprintf(f, "CLIENTID=%s\n", client_id_hex);
        }

        r = sd_dhcp_lease_get_vendor_specific(lease, &data, &data_len);
        if (r >= 0) {
                _cleanup_free_ char *option_hex = NULL;

                option_hex = hexmem(data, data_len);
                if (!option_hex)
                        return -ENOMEM;
                fprintf(f, "VENDOR_SPECIFIC=%s\n", option_hex);
        }

        LIST_FOREACH(options, option, lease->private_options) {
                char key[STRLEN("OPTION_000")+1];

                xsprintf(key, "OPTION_%" PRIu8, option->tag);
                r = serialize_dhcp_option(f, key, option->data, option->length);
                if (r < 0)
                        return r;
        }

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        r = conservative_rename(temp_path, lease_file);
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

int dhcp_lease_load(sd_dhcp_lease **ret, const char *lease_file) {
        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        _cleanup_free_ char
                *address = NULL,
                *router = NULL,
                *netmask = NULL,
                *server_address = NULL,
                *next_server = NULL,
                *broadcast = NULL,
                *dns = NULL,
                *ntp = NULL,
                *sip = NULL,
                *pop3 = NULL,
                *smtp = NULL,
                *lpr = NULL,
                *mtu = NULL,
                *static_routes = NULL,
                *classless_routes = NULL,
                *domains = NULL,
                *client_id_hex = NULL,
                *vendor_specific_hex = NULL,
                *lifetime = NULL,
                *t1 = NULL,
                *t2 = NULL;
        _cleanup_(private_options_freep) char **options = NULL;

        int r, i;

        assert(lease_file);
        assert(ret);

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        options = new0(char*, SD_DHCP_OPTION_PRIVATE_LAST - SD_DHCP_OPTION_PRIVATE_BASE + 1);
        if (!options)
                return -ENOMEM;

        r = parse_env_file(NULL, lease_file,
                           "ADDRESS", &address,
                           "ROUTER", &router,
                           "NETMASK", &netmask,
                           "SERVER_ADDRESS", &server_address,
                           "NEXT_SERVER", &next_server,
                           "BROADCAST", &broadcast,
                           "DNS", &dns,
                           "NTP", &ntp,
                           "SIP", &sip,
                           "POP3", &pop3,
                           "SMTP", &smtp,
                           "LPR", &lpr,
                           "MTU", &mtu,
                           "DOMAINNAME", &lease->domainname,
                           "HOSTNAME", &lease->hostname,
                           "DOMAIN_SEARCH_LIST", &domains,
                           "ROOT_PATH", &lease->root_path,
                           "STATIC_ROUTES", &static_routes,
                           "CLASSLESS_ROUTES", &classless_routes,
                           "CLIENTID", &client_id_hex,
                           "TIMEZONE", &lease->timezone,
                           "VENDOR_SPECIFIC", &vendor_specific_hex,
                           "LIFETIME", &lifetime,
                           "T1", &t1,
                           "T2", &t2,
                           "OPTION_224", &options[0],
                           "OPTION_225", &options[1],
                           "OPTION_226", &options[2],
                           "OPTION_227", &options[3],
                           "OPTION_228", &options[4],
                           "OPTION_229", &options[5],
                           "OPTION_230", &options[6],
                           "OPTION_231", &options[7],
                           "OPTION_232", &options[8],
                           "OPTION_233", &options[9],
                           "OPTION_234", &options[10],
                           "OPTION_235", &options[11],
                           "OPTION_236", &options[12],
                           "OPTION_237", &options[13],
                           "OPTION_238", &options[14],
                           "OPTION_239", &options[15],
                           "OPTION_240", &options[16],
                           "OPTION_241", &options[17],
                           "OPTION_242", &options[18],
                           "OPTION_243", &options[19],
                           "OPTION_244", &options[20],
                           "OPTION_245", &options[21],
                           "OPTION_246", &options[22],
                           "OPTION_247", &options[23],
                           "OPTION_248", &options[24],
                           "OPTION_249", &options[25],
                           "OPTION_250", &options[26],
                           "OPTION_251", &options[27],
                           "OPTION_252", &options[28],
                           "OPTION_253", &options[29],
                           "OPTION_254", &options[30]);
        if (r < 0)
                return r;

        if (address) {
                r = inet_pton(AF_INET, address, &lease->address);
                if (r <= 0)
                        log_debug("Failed to parse address %s, ignoring.", address);
        }

        if (router) {
                r = deserialize_in_addrs(&lease->router, router);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize router addresses %s, ignoring: %m", router);
                else
                        lease->router_size = r;
        }

        if (netmask) {
                r = inet_pton(AF_INET, netmask, &lease->subnet_mask);
                if (r <= 0)
                        log_debug("Failed to parse netmask %s, ignoring.", netmask);
                else
                        lease->have_subnet_mask = true;
        }

        if (server_address) {
                r = inet_pton(AF_INET, server_address, &lease->server_address);
                if (r <= 0)
                        log_debug("Failed to parse server address %s, ignoring.", server_address);
        }

        if (next_server) {
                r = inet_pton(AF_INET, next_server, &lease->next_server);
                if (r <= 0)
                        log_debug("Failed to parse next server %s, ignoring.", next_server);
        }

        if (broadcast) {
                r = inet_pton(AF_INET, broadcast, &lease->broadcast);
                if (r <= 0)
                        log_debug("Failed to parse broadcast address %s, ignoring.", broadcast);
                else
                        lease->have_broadcast = true;
        }

        if (dns) {
                r = deserialize_in_addrs(&lease->servers[SD_DHCP_LEASE_DNS].addr, dns);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize DNS servers %s, ignoring: %m", dns);
                else
                        lease->servers[SD_DHCP_LEASE_DNS].size = r;
        }

        if (ntp) {
                r = deserialize_in_addrs(&lease->servers[SD_DHCP_LEASE_NTP].addr, ntp);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize NTP servers %s, ignoring: %m", ntp);
                else
                        lease->servers[SD_DHCP_LEASE_NTP].size = r;
        }

        if (sip) {
                r = deserialize_in_addrs(&lease->servers[SD_DHCP_LEASE_SIP].addr, sip);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize SIP servers %s, ignoring: %m", sip);
                else
                        lease->servers[SD_DHCP_LEASE_SIP].size = r;
        }

        if (pop3) {
                r = deserialize_in_addrs(&lease->servers[SD_DHCP_LEASE_POP3].addr, pop3);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize POP3 server %s, ignoring: %m", pop3);
                else
                        lease->servers[SD_DHCP_LEASE_POP3].size = r;
        }

        if (smtp) {
                r = deserialize_in_addrs(&lease->servers[SD_DHCP_LEASE_SMTP].addr, smtp);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize SMTP server %s, ignoring: %m", smtp);
                else
                        lease->servers[SD_DHCP_LEASE_SMTP].size = r;
        }

        if (lpr) {
                r = deserialize_in_addrs(&lease->servers[SD_DHCP_LEASE_LPR].addr, lpr);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize LPR server %s, ignoring: %m", lpr);
                else
                        lease->servers[SD_DHCP_LEASE_LPR].size = r;
        }

        if (mtu) {
                r = safe_atou16(mtu, &lease->mtu);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse MTU %s, ignoring: %m", mtu);
        }

        if (domains) {
                _cleanup_strv_free_ char **a = NULL;
                a = strv_split(domains, " ");
                if (!a)
                        return -ENOMEM;

                if (!strv_isempty(a))
                        lease->search_domains = TAKE_PTR(a);
        }

        if (static_routes) {
                r = deserialize_dhcp_routes(
                                &lease->static_routes,
                                &lease->n_static_routes,
                                static_routes);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse DHCP static routes %s, ignoring: %m", static_routes);
        }

        if (classless_routes) {
                r = deserialize_dhcp_routes(
                                &lease->classless_routes,
                                &lease->n_classless_routes,
                                classless_routes);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse DHCP classless routes %s, ignoring: %m", classless_routes);
        }

        if (lifetime) {
                r = parse_sec(lifetime, &lease->lifetime);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse lifetime %s, ignoring: %m", lifetime);
        }

        if (t1) {
                r = parse_sec(t1, &lease->t1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T1 %s, ignoring: %m", t1);
        }

        if (t2) {
                r = parse_sec(t2, &lease->t2);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T2 %s, ignoring: %m", t2);
        }

        if (client_id_hex) {
                _cleanup_free_ void *data = NULL;
                size_t data_size;

                r = unhexmem(client_id_hex, SIZE_MAX, &data, &data_size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse client ID %s, ignoring: %m", client_id_hex);

                r = sd_dhcp_client_id_set_raw(&lease->client_id, data, data_size);
                if (r < 0)
                        log_debug_errno(r, "Failed to assign client ID, ignoring: %m");
        }

        if (vendor_specific_hex) {
                r = unhexmem(vendor_specific_hex, SIZE_MAX, &lease->vendor_specific, &lease->vendor_specific_len);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse vendor specific data %s, ignoring: %m", vendor_specific_hex);
        }

        for (i = 0; i <= SD_DHCP_OPTION_PRIVATE_LAST - SD_DHCP_OPTION_PRIVATE_BASE; i++) {
                _cleanup_free_ void *data = NULL;
                size_t len;

                if (!options[i])
                        continue;

                r = unhexmem(options[i], SIZE_MAX, &data, &len);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse private DHCP option %s, ignoring: %m", options[i]);
                        continue;
                }

                r = dhcp_lease_insert_private_option(lease, SD_DHCP_OPTION_PRIVATE_BASE + i, data, len);
                if (r < 0)
                        return r;
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

int sd_dhcp_lease_get_timezone(sd_dhcp_lease *lease, const char **tz) {
        assert_return(lease, -EINVAL);
        assert_return(tz, -EINVAL);

        if (!lease->timezone)
                return -ENODATA;

        *tz = lease->timezone;
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
