/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <sys/stat.h>

#include "sd-dhcp-lease.h"

#include "alloc-util.h"
#include "dhcp-client-internal.h"
#include "dhcp-lease-internal.h"
#include "dhcp-option.h"
#include "dhcp-route.h"  /* IWYU pragma: keep */
#include "dns-resolver-internal.h"
#include "in-addr-util.h"
#include "ip-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

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

        if (!triple_timestamp_is_set(&lease->timestamp))
                return -ENODATA;

        if (ret)
                *ret = triple_timestamp_by_clock(&lease->timestamp, clock);
        return 0;
}

int sd_dhcp_lease_get_address(sd_dhcp_lease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->address == INADDR_ANY)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->address;
        return 0;
}

int sd_dhcp_lease_get_broadcast(sd_dhcp_lease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->broadcast == INADDR_ANY)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->broadcast;
        return 0;
}

int sd_dhcp_lease_get_lifetime(sd_dhcp_lease *lease, uint64_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->lifetime <= 0)
                return -ENODATA;

        if (ret)
                *ret = lease->lifetime;
        return 0;
}

int sd_dhcp_lease_get_t1(sd_dhcp_lease *lease, uint64_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->t1 <= 0)
                return -ENODATA;

        if (ret)
                *ret = lease->t1;
        return 0;
}

int sd_dhcp_lease_get_t2(sd_dhcp_lease *lease, uint64_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->t2 <= 0)
                return -ENODATA;

        if (ret)
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
                assert_return(lease, -EINVAL);                          \
                                                                        \
                r = sd_dhcp_lease_get_##name(lease, &t);                \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = sd_dhcp_lease_get_timestamp(lease, clock, &timestamp); \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (ret)                                                \
                        *ret = usec_add(t, timestamp);                  \
                return 0;                                               \
        }

DEFINE_GET_TIMESTAMP(lifetime);
DEFINE_GET_TIMESTAMP(t1);
DEFINE_GET_TIMESTAMP(t2);

int sd_dhcp_lease_get_mtu(sd_dhcp_lease *lease, uint16_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->mtu <= 0)
                return -ENODATA;

        if (ret)
                *ret = lease->mtu;
        return 0;
}

int sd_dhcp_lease_get_servers(
                sd_dhcp_lease *lease,
                sd_dhcp_lease_server_type_t what,
                const struct in_addr **ret) {

        assert_return(lease, -EINVAL);
        assert_return(what >= 0, -EINVAL);
        assert_return(what < _SD_DHCP_LEASE_SERVER_TYPE_MAX, -EINVAL);

        if (lease->servers[what].size <= 0)
                return -ENODATA;

        if (ret)
                *ret = lease->servers[what].addr;

        return (int) lease->servers[what].size;
}

int sd_dhcp_lease_get_dns(sd_dhcp_lease *lease, const struct in_addr **ret) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_DNS, ret);
}
int sd_dhcp_lease_get_ntp(sd_dhcp_lease *lease, const struct in_addr **ret) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_NTP, ret);
}
int sd_dhcp_lease_get_sip(sd_dhcp_lease *lease, const struct in_addr **ret) {
        return sd_dhcp_lease_get_servers(lease, SD_DHCP_LEASE_SIP, ret);
}

int sd_dhcp_lease_get_domainname(sd_dhcp_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->domainname)
                return -ENODATA;

        if (ret)
                *ret = lease->domainname;
        return 0;
}

int sd_dhcp_lease_get_hostname(sd_dhcp_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->hostname)
                return -ENODATA;

        if (ret)
                *ret = lease->hostname;
        return 0;
}

int sd_dhcp_lease_get_captive_portal(sd_dhcp_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->captive_portal)
                return -ENODATA;

        if (ret)
                *ret = lease->captive_portal;
        return 0;
}

int sd_dhcp_lease_get_dnr(sd_dhcp_lease *lease, sd_dns_resolver **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->dnr)
                return -ENODATA;

        if (ret)
                *ret = lease->dnr;
        return lease->n_dnr;
}

int sd_dhcp_lease_get_router(sd_dhcp_lease *lease, const struct in_addr **ret) {
        assert_return(lease, -EINVAL);

        if (lease->router_size <= 0)
                return -ENODATA;

        if (ret)
                *ret = lease->router;
        return (int) lease->router_size;
}

int sd_dhcp_lease_get_netmask(sd_dhcp_lease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->subnet_mask == INADDR_ANY)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->subnet_mask;
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

int sd_dhcp_lease_get_server_identifier(sd_dhcp_lease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->server_address == INADDR_ANY)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->server_address;
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

int sd_dhcp_lease_get_search_domains(sd_dhcp_lease *lease, char ***ret) {
        assert_return(lease, -EINVAL);

        size_t n = strv_length(lease->search_domains);
        if (n == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->search_domains;
        return (int) n;
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

static sd_dhcp_lease* dhcp_lease_free(sd_dhcp_lease *lease) {
        assert(lease);

        sd_dhcp_message_unref(lease->message);

        free(lease->router);
        free(lease->timezone);
        free(lease->hostname);
        free(lease->domainname);
        free(lease->captive_portal);

        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(lease->servers[i].addr);

        dns_resolver_free_array(lease->dnr, lease->n_dnr);
        free(lease->static_routes);
        free(lease->classless_routes);
        strv_free(lease->search_domains);
        free(lease->sixrd_br_addresses);
        return mfree(lease);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_lease, sd_dhcp_lease, dhcp_lease_free);

int dhcp_lease_new(sd_dhcp_lease **ret) {
        sd_dhcp_lease *lease;

        assert(ret);

        lease = new0(sd_dhcp_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->n_ref = 1;

        *ret = lease;
        return 0;
}

int sd_dhcp_lease_get_timezone(sd_dhcp_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->timezone)
                return -ENODATA;

        if (ret)
                *ret = lease->timezone;
        return 0;
}

static int dhcp_lease_new_from_message(sd_dhcp_client *client, sd_dhcp_message *message, sd_dhcp_lease **ret) {
        int r;

        assert(client);
        assert(message);
        assert(ret);

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        /* acquired address: mandatory */
        if (message->header.yiaddr == INADDR_ANY)
                return -EBADMSG;
        lease->address = message->header.yiaddr;

        /* subnet mask: mandatory */
        if (dhcp_message_get_option_be32(message, SD_DHCP_OPTION_SUBNET_MASK, &lease->subnet_mask) < 0) {
                /* fall back to the default subnet masks based on address class */
                struct in_addr mask;
                r = in4_addr_default_subnet_mask(
                                &(struct in_addr) {
                                        .s_addr = message->header.yiaddr,
                                },
                                &mask);
                if (r < 0)
                        return r;

                lease->subnet_mask = mask.s_addr;
        }

        /* DHCP server address: mandatory */
        r = dhcp_message_get_option_be32(message, SD_DHCP_OPTION_SERVER_IDENTIFIER, &lease->server_address);
        if (r < 0) {
                if (!client->bootp)
                        return log_dhcp_client_errno(client, r, "Failed to read %s option: %m",
                                                     dhcp_option_code_to_string(SD_DHCP_OPTION_SERVER_IDENTIFIER));

                /* BOOTP typically does not use Server Identifier option, but uses the siaddr field. */
                lease->server_address = message->header.siaddr;
        }

        /* lifetime: mandatory */
        if (client->bootp)
                lease->lifetime = USEC_INFINITY; /* BOOTP does not support lifetime. */
        else {
                r = dhcp_message_get_option_sec(message, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, /* max_as_infinity= */ true, &lease->lifetime);
                if (r < 0 || lease->lifetime == 0) {
                        if (client->fallback_lease_lifetime == 0) {
                                if (r < 0)
                                        return log_dhcp_client_errno(client, r, "Failed to read %s option: %m",
                                                                     dhcp_option_code_to_string(SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME));

                                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                                             "The %s option set to 0 second.",
                                                             dhcp_option_code_to_string(SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME));
                        }

                        lease->lifetime = client->fallback_lease_lifetime;
                }

                /* There is nothing mentioned about the valid range of the lifetime in RFC, but if it is too
                 * short, then the network connection easily become unstable. Let's bump to 30 seconds in
                 * that case.
                 * TODO: filter short lifetime in selecting state. */
                if (lease->lifetime <= 30 * USEC_PER_SEC) {
                        log_dhcp_client(client, "The %s option is too short (%s), bumping lease lifetime to 30 seconds.",
                                        dhcp_option_code_to_string(SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME),
                                        FORMAT_TIMESPAN(lease->lifetime, USEC_PER_SEC));
                        lease->lifetime = 30 * USEC_PER_SEC;
                }

                if (lease->lifetime != USEC_INFINITY) {
                        /* T2 */
                        r = dhcp_message_get_option_sec(message, SD_DHCP_OPTION_REBINDING_TIME, /* max_as_infinity= */ true, &lease->t2);
                        if (r < 0 && r != -ENODATA)
                                log_dhcp_client_errno(client, r, "Failed to read %s option, ignoring: %m",
                                                      dhcp_option_code_to_string(SD_DHCP_OPTION_REBINDING_TIME));

                        /* verify that 0 < t2 < lifetime */
                        if (lease->t2 <= 0 || lease->t2 >= lease->lifetime)
                                /* RFC2131 section 4.4.5: T2 defaults to (0.875 * duration_of_lease). */
                                lease->t2 = lease->lifetime * 7 / 8;

                        /* T1 */
                        r = dhcp_message_get_option_sec(message, SD_DHCP_OPTION_RENEWAL_TIME, /* max_as_infinity= */ true, &lease->t1);
                        if (r < 0 && r != -ENODATA)
                                log_dhcp_client_errno(client, r, "Failed to read %s option, ignoring: %m",
                                                      dhcp_option_code_to_string(SD_DHCP_OPTION_RENEWAL_TIME));

                        /* verify that 0 < t1 < t2 */
                        if (lease->t1 <= 0 || lease->t1 >= lease->t2)
                                /* RFC2131 section 4.4.5: T1 defaults to (0.5 * duration_of_lease). */
                                lease->t1 = lease->lifetime / 2;

                        /* For the case when T2 is too small compared with lifetime. */
                        if (lease->t1 >= lease->t2)
                                /* RFC2131 section 4.4.5: T2 defaults to (0.875 * duration_of_lease). */
                                lease->t2 = lease->lifetime * 7 / 8;

                        assert(lease->t1 > 0);
                        assert(lease->t1 < lease->t2);
                        assert(lease->t2 < lease->lifetime);
                }
        }

        r = dhcp_message_get_option_be32(message, SD_DHCP_OPTION_BROADCAST, &lease->broadcast);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_BROADCAST));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_ROUTER,
                        &lease->router_size,
                        &lease->router);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_ROUTER));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                        &lease->servers[SD_DHCP_LEASE_DNS].size,
                        &lease->servers[SD_DHCP_LEASE_DNS].addr);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_DOMAIN_NAME_SERVER));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_NTP_SERVER,
                        &lease->servers[SD_DHCP_LEASE_NTP].size,
                        &lease->servers[SD_DHCP_LEASE_NTP].addr);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_NTP_SERVER));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_SIP_SERVER,
                        &lease->servers[SD_DHCP_LEASE_SIP].size,
                        &lease->servers[SD_DHCP_LEASE_SIP].addr);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_SIP_SERVER));

        r = dhcp_message_get_option_routes(
                        message,
                        SD_DHCP_OPTION_STATIC_ROUTE,
                        &lease->n_static_routes,
                        &lease->static_routes);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_STATIC_ROUTE));

        r = dhcp_message_get_option_routes(
                        message,
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                        &lease->n_classless_routes,
                        &lease->classless_routes);
        if (r < 0) {
                if (r != -ENODATA)
                        log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                              dhcp_option_code_to_string(SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE));

                r = dhcp_message_get_option_routes(
                                message,
                                SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE,
                                &lease->n_classless_routes,
                                &lease->classless_routes);
                if (r < 0 && r != -ENODATA)
                        log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                              dhcp_option_code_to_string(SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE));
        }

        r = dhcp_message_get_option_6rd(
                        message,
                        &lease->sixrd_ipv4masklen,
                        &lease->sixrd_prefixlen,
                        &lease->sixrd_prefix,
                        &lease->sixrd_n_br_addresses,
                        &lease->sixrd_br_addresses);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_6RD));

        r = dhcp_message_get_option_dns_name(message, SD_DHCP_OPTION_DOMAIN_NAME, &lease->domainname);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_DOMAIN_NAME));

        r = dhcp_message_get_option_hostname(message, &lease->hostname);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s and/or %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_FQDN),
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_HOST_NAME));

        r = dhcp_message_get_option_domains(message, SD_DHCP_OPTION_DOMAIN_SEARCH, &lease->search_domains);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_DOMAIN_SEARCH));

        r = dhcp_message_get_option_dnr(message, &lease->n_dnr, &lease->dnr);
        if (r < 0 && r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_V4_DNR));

        _cleanup_free_ char *captive_portal = NULL;
        r = dhcp_message_get_option_string(message, SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL, &captive_portal);
        if (r >= 0) {
                if (!in_charset(captive_portal, URI_VALID))
                        log_dhcp_client(client, "Received invalid %s, ignoring: %s",
                                        dhcp_option_code_to_string(SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL),
                                        captive_portal);
                else
                        lease->captive_portal = TAKE_PTR(captive_portal);
        } else if (r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL));

        _cleanup_free_ char *tz = NULL;
        r = dhcp_message_get_option_string(message, SD_DHCP_OPTION_TZDB_TIMEZONE, &tz);
        if (r >= 0) {
                if (!timezone_is_valid(tz, LOG_DEBUG))
                        log_dhcp_client(client, "Received invalid %s, ignoring: %s",
                                        dhcp_option_code_to_string(SD_DHCP_OPTION_TZDB_TIMEZONE), tz);
                else
                        lease->timezone = TAKE_PTR(tz);
        } else if (r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_TZDB_TIMEZONE));

        uint16_t mtu;
        r = dhcp_message_get_option_u16(message, SD_DHCP_OPTION_MTU_INTERFACE, &mtu);
        if (r >= 0) {
                /* RFC 2132 section 5.1 permits MTU values down to 68 bytes, which corresponds to the minimum
                 * IPv4 datagram size defined in RFC 791.
                 *
                 * Such a small MTU is not generally usable for normal IP communication. RFC 791 and RFC 1122
                 * require hosts to be able to reassemble datagrams of at least 576 bytes, which is treated
                 * as the minimum safe size for IPv4 interoperability.
                 *
                 * Ignore MTU values smaller than 576 bytes. */
                if (mtu < IPV4_MIN_REASSEMBLY_SIZE)
                        log_dhcp_client(client, "Received too small %s, ignoring: %u",
                                        dhcp_option_code_to_string(SD_DHCP_OPTION_MTU_INTERFACE), mtu);
                else
                        lease->mtu = mtu;
        } else if (r != -ENODATA)
                log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_MTU_INTERFACE));

        /* RFC 8925 section 3.2
         * If the client did not include the IPv6-Only Preferred option code in the Parameter Request List in
         * the DHCPDISCOVER or DHCPREQUEST message, it MUST ignore the IPv6-Only Preferred option in any
         * messages received from the server. */
        if (!client->anonymize &&
            set_contains(client->req_opts, UINT_TO_PTR(SD_DHCP_OPTION_IPV6_ONLY_PREFERRED))) {
                usec_t t;
                r = dhcp_message_get_option_sec(
                                message,
                                SD_DHCP_OPTION_IPV6_ONLY_PREFERRED,
                                /* max_as_infinity= */ false,
                                &t);
                if (r >= 0) {
                        /* RFC 8925 section 3.4
                         * MIN_V6ONLY_WAIT: The lower boundary for V6ONLY_WAIT. */
                        if (t < MIN_V6ONLY_WAIT_USEC && !network_test_mode_enabled())
                                lease->ipv6_only_preferred_usec = MIN_V6ONLY_WAIT_USEC;
                        else
                                lease->ipv6_only_preferred_usec = t;
                } else if (r != -ENODATA)
                        log_dhcp_client_errno(client, r, "Failed to parse %s option, ignoring: %m",
                                              dhcp_option_code_to_string(SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        }

        lease->message = sd_dhcp_message_ref(message);
        *ret = TAKE_PTR(lease);
        return 0;
}

static int client_parse_bootreply(sd_dhcp_client *client, sd_dhcp_message *message, sd_dhcp_lease **ret) {
        int r;

        assert(client);
        assert(message);
        assert(ret);

        if (client->state != DHCP_STATE_SELECTING)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG), "Received unexpected BOOTREPLY.");

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        r = dhcp_lease_new_from_message(client, message, &lease);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to create BOOTP lease: %m");

        log_dhcp_client(client, "Received BOOTREPLY from %s", IN4_ADDR_TO_STRING(&(struct in_addr) { .s_addr = lease->server_address }));

        *ret = TAKE_PTR(lease);
        return DHCP_ACK;
}

static int client_parse_ack(sd_dhcp_client *client, sd_dhcp_message *message, sd_dhcp_lease **ret) {
        int r;

        assert(client);
        assert(message);
        assert(ret);

        switch (client->state) {
        case DHCP_STATE_SELECTING:
                if (!client->rapid_commit)
                        return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG), "Received unexpected DHCPACK.");

                r = dhcp_message_get_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return log_dhcp_client_errno(client, r, "Failed to get Rapid Commit option: %m");

                break;
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                break;
        default:
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG), "Received unexpected DHCPACK.");
        }

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        r = dhcp_lease_new_from_message(client, message, &lease);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to create DHCP lease: %m");

        log_dhcp_client(client, "Received DHCPACK from %s", IN4_ADDR_TO_STRING(&(struct in_addr) { .s_addr = lease->server_address }));

        *ret = TAKE_PTR(lease);
        return DHCP_ACK;
}

static int client_parse_offer(sd_dhcp_client *client, sd_dhcp_message *message, sd_dhcp_lease **ret) {
        int r;

        assert(client);
        assert(message);
        assert(ret);

        if (client->state != DHCP_STATE_SELECTING)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG), "Received unexpected DHCPOFFER.");

        _cleanup_(sd_dhcp_lease_unrefp) sd_dhcp_lease *lease = NULL;
        r = dhcp_lease_new_from_message(client, message, &lease);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to create DHCP lease: %m");

        log_dhcp_client(client, "Received DHCPOFFER from %s", IN4_ADDR_TO_STRING(&(struct in_addr) { .s_addr = lease->server_address }));

        *ret = TAKE_PTR(lease);
        return DHCP_OFFER;
}

static int client_parse_nak(sd_dhcp_client *client, sd_dhcp_message *message, sd_dhcp_lease **ret) {
        int r;

        assert(client);
        assert(message);
        assert(ret);

        /* DHCPNAK is a valid reply when we sent DHCPREQUEST. When we receive it after sending
         * DHCPDISCOVER (or even we sent nothing), we should ignore the message. */
        if (!IN_SET(client->state, DHCP_STATE_REBOOTING, DHCP_STATE_REQUESTING, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING))
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG), "Received unexpected DHCPNAK.");

        /* Always ignore DHCPNAK without Server Identifier option. */
        struct in_addr a;
        r = dhcp_message_get_option_address(message, SD_DHCP_OPTION_SERVER_IDENTIFIER, &a);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to read Server Identifier option in DHCPNAK: %m");

        if (client->lease && client->lease->server_address != a.s_addr)
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG),
                                             "Received DHCPNAK from unexpected server (%s).",
                                             IN4_ADDR_TO_STRING(&a));

        _cleanup_free_ char *e = NULL;
        (void) dhcp_message_get_option_string(message, SD_DHCP_OPTION_ERROR_MESSAGE, &e);
        log_dhcp_client(client, "Received DHCPNAK: %s", strna(e));

        *ret = NULL;
        return DHCP_NAK;
}

int dhcp_client_parse_message(sd_dhcp_client *client, const struct iovec *iov, sd_dhcp_lease **ret) {
        int r;

        assert(client);
        assert(iov);
        assert(ret);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_parse(
                        iov,
                        BOOTREPLY,
                        &client->xid,
                        client->arp_type,
                        &client->hw_addr,
                        &message);
        if (r < 0)
                return r;

        if (client->bootp)
                return client_parse_bootreply(client, message, ret);

        uint8_t type;
        r = dhcp_message_get_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, &type);
        if (r < 0)
                return log_dhcp_client_errno(client, r, "Failed to read Message Type option: %m");

        switch (type) {
        case DHCP_OFFER:
                return client_parse_offer(client, message, ret);
        case DHCP_ACK:
                return client_parse_ack(client, message, ret);
        case DHCP_NAK:
                return client_parse_nak(client, message, ret);
        default:
                return log_dhcp_client_errno(client, SYNTHETIC_ERRNO(EBADMSG), "Received message with unexpected type (%u).", type);
        }
}
