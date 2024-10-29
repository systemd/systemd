/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <errno.h>

#include "alloc-util.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dns-domain.h"
#include "network-common.h"
#include "sort-util.h"
#include "strv.h"
#include "unaligned.h"

#define IRT_DEFAULT (1 * USEC_PER_DAY)
#define IRT_MINIMUM (600 * USEC_PER_SEC)

static void dhcp6_lease_set_timestamp(sd_dhcp6_lease *lease, const triple_timestamp *timestamp) {
        assert(lease);

        if (timestamp && triple_timestamp_is_set(timestamp))
                lease->timestamp = *timestamp;
        else
                triple_timestamp_now(&lease->timestamp);
}

int sd_dhcp6_lease_get_timestamp(sd_dhcp6_lease *lease, clockid_t clock, uint64_t *ret) {
        assert_return(lease, -EINVAL);
        assert_return(TRIPLE_TIMESTAMP_HAS_CLOCK(clock), -EOPNOTSUPP);
        assert_return(clock_supported(clock), -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        if (!triple_timestamp_is_set(&lease->timestamp))
                return -ENODATA;

        *ret = triple_timestamp_by_clock(&lease->timestamp, clock);
        return 0;
}

static void dhcp6_lease_set_lifetime(sd_dhcp6_lease *lease) {
        usec_t t1 = USEC_INFINITY, t2 = USEC_INFINITY, min_valid_lt = USEC_INFINITY;

        assert(lease);
        assert(lease->ia_na || lease->ia_pd);

        if (lease->ia_na) {
                t1 = MIN(t1, be32_sec_to_usec(lease->ia_na->header.lifetime_t1, /* max_as_infinity = */ true));
                t2 = MIN(t2, be32_sec_to_usec(lease->ia_na->header.lifetime_t2, /* max_as_infinity = */ true));

                LIST_FOREACH(addresses, a, lease->ia_na->addresses)
                        min_valid_lt = MIN(min_valid_lt, be32_sec_to_usec(a->iaaddr.lifetime_valid, /* max_as_infinity = */ true));
        }

        if (lease->ia_pd) {
                t1 = MIN(t1, be32_sec_to_usec(lease->ia_pd->header.lifetime_t1, /* max_as_infinity = */ true));
                t2 = MIN(t2, be32_sec_to_usec(lease->ia_pd->header.lifetime_t2, /* max_as_infinity = */ true));

                LIST_FOREACH(addresses, a, lease->ia_pd->addresses)
                        min_valid_lt = MIN(min_valid_lt, be32_sec_to_usec(a->iapdprefix.lifetime_valid, /* max_as_infinity = */ true));
        }

        if (t2 == 0 || t2 > min_valid_lt) {
                /* If T2 is zero or longer than the minimum valid lifetime of the addresses or prefixes,
                 * then adjust lifetime with it. */
                t1 = min_valid_lt / 2;
                t2 = min_valid_lt / 10 * 8;
        }

        lease->lifetime_valid = min_valid_lt;
        lease->lifetime_t1 = t1;
        lease->lifetime_t2 = t2;
}

#define DEFINE_GET_TIME_FUNCTIONS(name, val)                            \
        int sd_dhcp6_lease_get_##name(                                  \
                        sd_dhcp6_lease *lease,                          \
                        uint64_t *ret) {                                \
                                                                        \
                assert_return(lease, -EINVAL);                          \
                                                                        \
                if (!lease->ia_na && !lease->ia_pd)                     \
                        return -ENODATA;                                \
                                                                        \
                if (ret)                                                \
                        *ret = lease->val;                              \
                return 0;                                               \
        }                                                               \
                                                                        \
        int sd_dhcp6_lease_get_##name##_timestamp(                      \
                        sd_dhcp6_lease *lease,                          \
                        clockid_t clock,                                \
                        uint64_t *ret) {                                \
                                                                        \
                usec_t s, t;                                            \
                int r;                                                  \
                                                                        \
                assert_return(lease, -EINVAL);                          \
                                                                        \
                r = sd_dhcp6_lease_get_##name(lease, &s);               \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = sd_dhcp6_lease_get_timestamp(lease, clock, &t);     \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (ret)                                                \
                        *ret = time_span_to_stamp(s, t);                \
                return 0;                                               \
        }

DEFINE_GET_TIME_FUNCTIONS(t1, lifetime_t1);
DEFINE_GET_TIME_FUNCTIONS(t2, lifetime_t1);
DEFINE_GET_TIME_FUNCTIONS(valid_lifetime, lifetime_valid);

static void dhcp6_lease_set_server_address(sd_dhcp6_lease *lease, const struct in6_addr *server_address) {
        assert(lease);

        if (server_address)
                lease->server_address = *server_address;
        else
                lease->server_address = (struct in6_addr) {};
}

int sd_dhcp6_lease_get_server_address(sd_dhcp6_lease *lease, struct in6_addr *ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = lease->server_address;
        return 0;
}

void dhcp6_ia_clear_addresses(DHCP6IA *ia) {
        assert(ia);

        LIST_FOREACH(addresses, a, ia->addresses)
                free(a);

        ia->addresses = NULL;
}

DHCP6IA *dhcp6_ia_free(DHCP6IA *ia) {
        if (!ia)
                return NULL;

        dhcp6_ia_clear_addresses(ia);

        return mfree(ia);
}

int dhcp6_lease_set_clientid(sd_dhcp6_lease *lease, const uint8_t *id, size_t len) {
        uint8_t *clientid = NULL;

        assert(lease);
        assert(id || len == 0);

        if (len > 0) {
                clientid = memdup(id, len);
                if (!clientid)
                        return -ENOMEM;
        }

        free_and_replace(lease->clientid, clientid);
        lease->clientid_len = len;

        return 0;
}

int dhcp6_lease_get_clientid(sd_dhcp6_lease *lease, uint8_t **ret_id, size_t *ret_len) {
        assert(lease);

        if (!lease->clientid)
                return -ENODATA;

        if (ret_id)
                *ret_id = lease->clientid;
        if (ret_len)
                *ret_len = lease->clientid_len;

        return 0;
}

int dhcp6_lease_set_serverid(sd_dhcp6_lease *lease, const uint8_t *id, size_t len) {
        uint8_t *serverid = NULL;

        assert(lease);
        assert(id || len == 0);

        if (len > 0) {
                serverid = memdup(id, len);
                if (!serverid)
                        return -ENOMEM;
        }

        free_and_replace(lease->serverid, serverid);
        lease->serverid_len = len;

        return 0;
}

int dhcp6_lease_get_serverid(sd_dhcp6_lease *lease, uint8_t **ret_id, size_t *ret_len) {
        assert(lease);

        if (!lease->serverid)
                return -ENODATA;

        if (ret_id)
                *ret_id = lease->serverid;
        if (ret_len)
                *ret_len = lease->serverid_len;
        return 0;
}

int dhcp6_lease_set_preference(sd_dhcp6_lease *lease, uint8_t preference) {
        assert(lease);

        lease->preference = preference;
        return 0;
}

int dhcp6_lease_get_preference(sd_dhcp6_lease *lease, uint8_t *ret) {
        assert(lease);
        assert(ret);

        *ret = lease->preference;
        return 0;
}

int dhcp6_lease_set_rapid_commit(sd_dhcp6_lease *lease) {
        assert(lease);

        lease->rapid_commit = true;
        return 0;
}

int dhcp6_lease_get_rapid_commit(sd_dhcp6_lease *lease, bool *ret) {
        assert(lease);
        assert(ret);

        *ret = lease->rapid_commit;
        return 0;
}

int sd_dhcp6_lease_get_address(sd_dhcp6_lease *lease, struct in6_addr *ret) {
        assert_return(lease, -EINVAL);

        if (!lease->addr_iter)
                return -ENODATA;

        if (ret)
                *ret = lease->addr_iter->iaaddr.address;
        return 0;
}

int sd_dhcp6_lease_get_address_lifetime(
                sd_dhcp6_lease *lease,
                usec_t *ret_lifetime_preferred,
                usec_t *ret_lifetime_valid) {

        const struct iaaddr *a;

        assert_return(lease, -EINVAL);

        if (!lease->addr_iter)
                return -ENODATA;

        a = &lease->addr_iter->iaaddr;

        if (ret_lifetime_preferred)
                *ret_lifetime_preferred = be32_sec_to_usec(a->lifetime_preferred, /* max_as_infinity = */ true);
        if (ret_lifetime_valid)
                *ret_lifetime_valid = be32_sec_to_usec(a->lifetime_valid, /* max_as_infinity = */ true);
        return 0;
}

int sd_dhcp6_lease_address_iterator_reset(sd_dhcp6_lease *lease) {
        if (!lease)
                return false;

        lease->addr_iter = lease->ia_na ? lease->ia_na->addresses : NULL;
        return !!lease->addr_iter;
}

int sd_dhcp6_lease_address_iterator_next(sd_dhcp6_lease *lease) {
        if (!lease || !lease->addr_iter)
                return false;

        lease->addr_iter = lease->addr_iter->addresses_next;
        return !!lease->addr_iter;
}

int sd_dhcp6_lease_has_address(sd_dhcp6_lease *lease) {
        return lease && lease->ia_na;
}

int sd_dhcp6_lease_get_pd_prefix(
                sd_dhcp6_lease *lease,
                struct in6_addr *ret_prefix,
                uint8_t *ret_prefix_len) {

        const struct iapdprefix *a;

        assert_return(lease, -EINVAL);

        if (!lease->prefix_iter)
                return -ENODATA;

        a = &lease->prefix_iter->iapdprefix;

        if (ret_prefix)
                *ret_prefix = a->address;
        if (ret_prefix_len)
                *ret_prefix_len = a->prefixlen;
        return 0;
}

int sd_dhcp6_lease_get_pd_lifetime(
                sd_dhcp6_lease *lease,
                uint64_t *ret_lifetime_preferred,
                uint64_t *ret_lifetime_valid) {

        const struct iapdprefix *a;

        assert_return(lease, -EINVAL);

        if (!lease->prefix_iter)
                return -ENODATA;

        a = &lease->prefix_iter->iapdprefix;

        if (ret_lifetime_preferred)
                *ret_lifetime_preferred = be32_sec_to_usec(a->lifetime_preferred, /* max_as_infinity = */ true);
        if (ret_lifetime_valid)
                *ret_lifetime_valid = be32_sec_to_usec(a->lifetime_valid, /* max_as_infinity = */ true);
        return 0;
}

int sd_dhcp6_lease_pd_iterator_reset(sd_dhcp6_lease *lease) {
        if (!lease)
                return false;

        lease->prefix_iter = lease->ia_pd ? lease->ia_pd->addresses : NULL;
        return !!lease->prefix_iter;
}

int sd_dhcp6_lease_pd_iterator_next(sd_dhcp6_lease *lease) {
        if (!lease || !lease->prefix_iter)
                return false;

        lease->prefix_iter = lease->prefix_iter->addresses_next;
        return !!lease->prefix_iter;
}

#define DEFINE_GET_TIMESTAMP2(name)                                     \
        int sd_dhcp6_lease_get_##name##_lifetime_timestamp(             \
                        sd_dhcp6_lease *lease,                          \
                        clockid_t clock,                                \
                        uint64_t *ret_lifetime_preferred,               \
                        uint64_t *ret_lifetime_valid) {                 \
                                                                        \
                usec_t t, p, v;                                         \
                int r;                                                  \
                                                                        \
                assert_return(lease, -EINVAL);                          \
                                                                        \
                r = sd_dhcp6_lease_get_##name##_lifetime(               \
                                lease,                                  \
                                ret_lifetime_preferred ? &p : NULL,     \
                                ret_lifetime_valid ? &v : NULL);        \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = sd_dhcp6_lease_get_timestamp(lease, clock, &t);     \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (ret_lifetime_preferred)                             \
                        *ret_lifetime_preferred = time_span_to_stamp(p, t); \
                if (ret_lifetime_valid)                                 \
                        *ret_lifetime_valid = time_span_to_stamp(v, t); \
                return 0;                                               \
        }

DEFINE_GET_TIMESTAMP2(address);
DEFINE_GET_TIMESTAMP2(pd);

int sd_dhcp6_lease_has_pd_prefix(sd_dhcp6_lease *lease) {
        return lease && lease->ia_pd;
}

int dhcp6_lease_add_dns(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        assert(lease);
        assert(optval || optlen == 0);

        if (optlen == 0)
                return 0;

        return dhcp6_option_parse_addresses(optval, optlen, &lease->dns, &lease->dns_count);
}

int sd_dhcp6_lease_get_dns(sd_dhcp6_lease *lease, const struct in6_addr **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->dns)
                return -ENODATA;

        if (ret)
                *ret = lease->dns;

        return lease->dns_count;
}

int dhcp6_lease_add_domains(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        _cleanup_strv_free_ char **domains = NULL;
        int r;

        assert(lease);
        assert(optval || optlen == 0);

        if (optlen == 0)
                return 0;

        r = dhcp6_option_parse_domainname_list(optval, optlen, &domains);
        if (r < 0)
                return r;

        return strv_extend_strv_consume(&lease->domains, TAKE_PTR(domains), /* filter_duplicates = */ true);
}

int sd_dhcp6_lease_get_domains(sd_dhcp6_lease *lease, char ***ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->domains)
                return -ENODATA;

        *ret = lease->domains;
        return strv_length(lease->domains);
}

static int dhcp6_lease_add_dnr(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        int r;

        assert(lease);

        _cleanup_(sd_dns_resolver_done) sd_dns_resolver res = {};

        size_t offset = 0;

        /* priority */
        if (optlen - offset < sizeof(uint16_t))
                return -EBADMSG;
        res.priority = unaligned_read_be16(optval + offset);
        offset += sizeof(uint16_t);

        /* adn */
        if (optlen - offset < sizeof(uint16_t))
                return -EBADMSG;
        size_t ilen = unaligned_read_be16(optval + offset);
        offset += sizeof(uint16_t);
        if (offset + ilen > optlen)
                return -EBADMSG;

        r = dhcp6_option_parse_domainname(optval + offset, ilen, &res.auth_name);
        if (r < 0)
                return r;
        r = dns_name_is_valid_ldh(res.auth_name);
        if (r < 0)
                return r;
        if (!r)
                return -EBADMSG;
        offset += ilen;

        /* RFC9463 § 3.1.6: adn only mode */
        if (offset == optlen)
                return 0;

        /* addrs */
        if (optlen - offset < sizeof(uint16_t))
                return -EBADMSG;
        ilen = unaligned_read_be16(optval + offset);
        offset += sizeof(uint16_t);
        if (offset + ilen > optlen)
                return -EBADMSG;

        _cleanup_free_ struct in6_addr *addrs = NULL;
        size_t n_addrs = 0;

        r = dhcp6_option_parse_addresses(optval + offset, ilen, &addrs, &n_addrs);
        if (r < 0)
                return r;
        if (n_addrs == 0)
                return -EBADMSG;
        offset += ilen;

        res.addrs = new(union in_addr_union, n_addrs);
        if (!res.addrs)
                return -ENOMEM;

        for (size_t i = 0; i < n_addrs; i++) {
                union in_addr_union addr = {.in6 = addrs[i]};
                /* RFC9463 § 6.2 client MUST discard multicast and host loopback addresses */
                if (in_addr_is_multicast(AF_INET6, &addr) ||
                    in_addr_is_localhost(AF_INET6, &addr))
                        return -EBADMSG;
                res.addrs[i] = addr;
        }
        res.n_addrs = n_addrs;
        res.family = AF_INET6;

        /* svc params */
        r = dnr_parse_svc_params(optval + offset, optlen-offset, &res);
        if (r < 0)
                return r;

        /* Append this resolver */
        if (!GREEDY_REALLOC(lease->dnr, lease->n_dnr+1))
                return -ENOMEM;

        lease->dnr[lease->n_dnr++] = TAKE_STRUCT(res);

        typesafe_qsort(lease->dnr, lease->n_dnr, dns_resolver_prio_compare);

        return 1;
}

int sd_dhcp6_lease_get_dnr(sd_dhcp6_lease *lease, sd_dns_resolver **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->dnr)
                return -ENODATA;

        *ret = lease->dnr;
        return lease->n_dnr;
}

int dhcp6_lease_add_ntp(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        int r;

        assert(lease);
        assert(optval || optlen == 0);

        for (size_t offset = 0; offset < optlen;) {
                const uint8_t *subval;
                size_t sublen;
                uint16_t subopt;

                r = dhcp6_option_parse(optval, optlen, &offset, &subopt, &sublen, &subval);
                if (r < 0)
                        return r;

                switch (subopt) {
                case DHCP6_NTP_SUBOPTION_SRV_ADDR:
                case DHCP6_NTP_SUBOPTION_MC_ADDR:
                        if (sublen != 16)
                                return -EINVAL;

                        r = dhcp6_option_parse_addresses(subval, sublen, &lease->ntp, &lease->ntp_count);
                        if (r < 0)
                                return r;

                        break;

                case DHCP6_NTP_SUBOPTION_SRV_FQDN: {
                        _cleanup_free_ char *server = NULL;

                        r = dhcp6_option_parse_domainname(subval, sublen, &server);
                        if (r < 0)
                                return r;

                        if (strv_contains(lease->ntp_fqdn, server))
                                continue;

                        r = strv_consume(&lease->ntp_fqdn, TAKE_PTR(server));
                        if (r < 0)
                                return r;

                        break;
                }}
        }

        return 0;
}

int dhcp6_lease_add_sntp(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        assert(lease);
        assert(optval || optlen == 0);

        if (optlen == 0)
                return 0;

        /* SNTP option is defined in RFC4075, and deprecated by RFC5908. */
        return dhcp6_option_parse_addresses(optval, optlen, &lease->sntp, &lease->sntp_count);
}

int sd_dhcp6_lease_get_ntp_addrs(sd_dhcp6_lease *lease, const struct in6_addr **ret) {
        assert_return(lease, -EINVAL);

        if (lease->ntp) {
                if (ret)
                        *ret = lease->ntp;
                return lease->ntp_count;
        }

        if (lease->sntp && !lease->ntp_fqdn) {
                /* Fallback to the deprecated SNTP option. */
                if (ret)
                        *ret = lease->sntp;
                return lease->sntp_count;
        }

        return -ENODATA;
}

int sd_dhcp6_lease_get_ntp_fqdn(sd_dhcp6_lease *lease, char ***ret) {
        assert_return(lease, -EINVAL);

        if (!lease->ntp_fqdn)
                return -ENODATA;

        if (ret)
                *ret = lease->ntp_fqdn;
        return strv_length(lease->ntp_fqdn);
}

int dhcp6_lease_set_fqdn(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        char *fqdn;
        int r;

        assert(lease);
        assert(optval || optlen == 0);

        if (optlen == 0)
                return 0;

        if (optlen < 2)
                return -ENODATA;

        /* Ignore the flags field, it doesn't carry any useful
           information for clients. */
        r = dhcp6_option_parse_domainname(optval + 1, optlen - 1, &fqdn);
        if (r < 0)
                return r;

        return free_and_replace(lease->fqdn, fqdn);
}

int sd_dhcp6_lease_get_fqdn(sd_dhcp6_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->fqdn)
                return -ENODATA;

        *ret = lease->fqdn;
        return 0;
}

int dhcp6_lease_set_captive_portal(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        _cleanup_free_ char *uri = NULL;
        int r;

        assert(lease);
        assert(optval || optlen == 0);

        r = dhcp6_option_parse_string(optval, optlen, &uri);
        if (r < 0)
                return r;

        if (uri && !in_charset(uri, URI_VALID))
                return -EINVAL;

        return free_and_replace(lease->captive_portal, uri);
}

int sd_dhcp6_lease_get_captive_portal(sd_dhcp6_lease *lease, const char **ret) {
        assert_return(lease, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!lease->captive_portal)
                return -ENODATA;

        *ret = lease->captive_portal;
        return 0;
}

int sd_dhcp6_lease_get_vendor_options(sd_dhcp6_lease *lease, sd_dhcp6_option ***ret) {
        int r;

        assert_return(lease, -EINVAL);

        if (set_isempty(lease->vendor_options))
                return -ENODATA;

        if (ret) {
                if (!lease->sorted_vendor_options) {
                        r = set_dump_sorted(lease->vendor_options, (void***) &lease->sorted_vendor_options, NULL);
                        if (r < 0)
                                return r;
                }

                *ret = lease->sorted_vendor_options;
        }

        return set_size(lease->vendor_options);
}

static int dhcp6_lease_insert_vendor_option(
                sd_dhcp6_lease *lease,
                uint16_t option_code,
                const void *data,
                size_t len,
                uint32_t enterprise_id) {

        _cleanup_(sd_dhcp6_option_unrefp) sd_dhcp6_option *option = NULL;

        assert(lease);

        option = new(sd_dhcp6_option, 1);
        if (!option)
                return -ENOMEM;

        *option = (sd_dhcp6_option) {
                .n_ref = 1,
                .enterprise_identifier = enterprise_id,
                .option = option_code,
                .length = len,
        };
        option->data = memdup_suffix0(data, len);
        if (!option->data)
                return -ENOMEM;

        return set_ensure_consume(&lease->vendor_options, &dhcp6_option_hash_ops, TAKE_PTR(option));
}

static int dhcp6_lease_add_vendor_option(sd_dhcp6_lease *lease, const uint8_t *optval, size_t optlen) {
        int r;
        uint32_t enterprise_id;

        assert(lease);
        assert(optval || optlen == 0);

        if (optlen < sizeof(be32_t))
                return -EBADMSG;

        enterprise_id = unaligned_read_be32(optval);

        for (size_t offset = 4; offset < optlen;) {
                const uint8_t *subval;
                size_t sublen;
                uint16_t subopt;

                r = dhcp6_option_parse(optval, optlen, &offset, &subopt, &sublen, &subval);
                if (r < 0)
                        return r;

                r = dhcp6_lease_insert_vendor_option(lease, subopt, subval, sublen, enterprise_id);
                if (r < 0)
                        return r;
        }
        return 0;
}

static int dhcp6_lease_parse_message(
                sd_dhcp6_client *client,
                sd_dhcp6_lease *lease,
                const DHCP6Message *message,
                size_t len) {

        usec_t irt = IRT_DEFAULT;
        int r;

        assert(client);
        assert(lease);
        assert(message);
        assert(len >= sizeof(DHCP6Message));

        len -= sizeof(DHCP6Message);
        for (size_t offset = 0; offset < len;) {
                uint16_t optcode;
                size_t optlen;
                const uint8_t *optval;

                if (len - offset < offsetof(DHCP6Option, data)) {
                        log_dhcp6_client(client, "Ignoring %zu invalid byte(s) at the end of the packet", len - offset);
                        break;
                }

                r = dhcp6_option_parse(message->options, len, &offset, &optcode, &optlen, &optval);
                if (r < 0)
                        return log_dhcp6_client_errno(client, r,
                                                      "Failed to parse option header at offset %zu of total length %zu: %m",
                                                      offset, len);

                switch (optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        if (dhcp6_lease_get_clientid(lease, NULL, NULL) >= 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "%s contains multiple client IDs",
                                                              dhcp6_message_type_to_string(message->type));

                        r = dhcp6_lease_set_clientid(lease, optval, optlen);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set client ID: %m");

                        break;

                case SD_DHCP6_OPTION_SERVERID:
                        if (dhcp6_lease_get_serverid(lease, NULL, NULL) >= 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "%s contains multiple server IDs",
                                                              dhcp6_message_type_to_string(message->type));

                        r = dhcp6_lease_set_serverid(lease, optval, optlen);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set server ID: %m");

                        break;

                case SD_DHCP6_OPTION_PREFERENCE:
                        if (optlen != 1)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL), "Received invalid length for preference.");

                        r = dhcp6_lease_set_preference(lease, optval[0]);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set preference: %m");

                        break;

                case SD_DHCP6_OPTION_STATUS_CODE: {
                        _cleanup_free_ char *msg = NULL;

                        r = dhcp6_option_parse_status(optval, optlen, &msg);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to parse status code: %m");
                        if (r > 0)
                                return log_dhcp6_client_errno(client, dhcp6_message_status_to_errno(r),
                                                              "Received %s message with non-zero status%s%s",
                                                              dhcp6_message_type_to_string(message->type),
                                                              isempty(msg) ? "." : ": ", strempty(msg));
                        break;
                }
                case SD_DHCP6_OPTION_IA_NA: {
                        _cleanup_(dhcp6_ia_freep) DHCP6IA *ia = NULL;

                        if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                                log_dhcp6_client(client, "Ignoring IA NA option in information requesting mode.");
                                break;
                        }

                        r = dhcp6_option_parse_ia(client, client->ia_na.header.id, optcode, optlen, optval, &ia);
                        if (r == -ENOMEM)
                                return log_oom_debug();
                        if (r < 0) {
                                log_dhcp6_client_errno(client, r, "Failed to parse IA_NA option, ignoring: %m");
                                continue;
                        }

                        if (lease->ia_na) {
                                log_dhcp6_client(client, "Received duplicate matching IA_NA option, ignoring.");
                                continue;
                        }

                        free_and_replace_full(lease->ia_na, ia, dhcp6_ia_free);
                        break;
                }
                case SD_DHCP6_OPTION_IA_PD: {
                        _cleanup_(dhcp6_ia_freep) DHCP6IA *ia = NULL;

                        if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                                log_dhcp6_client(client, "Ignoring IA PD option in information requesting mode.");
                                break;
                        }

                        r = dhcp6_option_parse_ia(client, client->ia_pd.header.id, optcode, optlen, optval, &ia);
                        if (r == -ENOMEM)
                                return log_oom_debug();
                        if (r < 0) {
                                log_dhcp6_client_errno(client, r, "Failed to parse IA_PD option, ignoring: %m");
                                continue;
                        }

                        if (lease->ia_pd) {
                                log_dhcp6_client(client, "Received duplicate matching IA_PD option, ignoring.");
                                continue;
                        }

                        free_and_replace_full(lease->ia_pd, ia, dhcp6_ia_free);
                        break;
                }
                case SD_DHCP6_OPTION_RAPID_COMMIT:
                        if (optlen != 0)
                                log_dhcp6_client(client, "Received rapid commit option with an invalid length (%zu), ignoring.", optlen);

                        r = dhcp6_lease_set_rapid_commit(lease);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to set rapid commit flag: %m");

                        break;

                case SD_DHCP6_OPTION_DNS_SERVER:
                        r = dhcp6_lease_add_dns(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse DNS server option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_DOMAIN:
                        r = dhcp6_lease_add_domains(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse domain list option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_NTP_SERVER:
                        r = dhcp6_lease_add_ntp(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse NTP server option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_SNTP_SERVER:
                        r = dhcp6_lease_add_sntp(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse SNTP server option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_CAPTIVE_PORTAL:
                        r = dhcp6_lease_set_captive_portal(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse captive portal option, ignoring: %m");
                        break;

                case SD_DHCP6_OPTION_CLIENT_FQDN:
                        r = dhcp6_lease_set_fqdn(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse FQDN option, ignoring: %m");

                        break;

                case SD_DHCP6_OPTION_INFORMATION_REFRESH_TIME:
                        if (optlen != 4)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                                              "Received information refresh time option with an invalid length (%zu).", optlen);

                        irt = unaligned_be32_sec_to_usec(optval, /* max_as_infinity = */ false);
                        break;

                case SD_DHCP6_OPTION_V6_DNR:
                        r = dhcp6_lease_add_dnr(lease, optval, optlen);
                        if (r < 0)
                                return log_dhcp6_client_errno(client, r, "Failed to parse DNR option, ignoring: %m");
                        if (r == 0)
                                log_dhcp6_client(client, "Received ADN-only DNRv6 option, ignoring.");

                        break;

                case SD_DHCP6_OPTION_VENDOR_OPTS:
                        r = dhcp6_lease_add_vendor_option(lease, optval, optlen);
                        if (r < 0)
                                log_dhcp6_client_errno(client, r, "Failed to parse vendor option, ignoring: %m");

                        break;
                }
        }

        uint8_t *clientid;
        size_t clientid_len;
        if (dhcp6_lease_get_clientid(lease, &clientid, &clientid_len) < 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "%s message does not contain client ID. Ignoring.",
                                              dhcp6_message_type_to_string(message->type));

        if (memcmp_nn(clientid, clientid_len, &client->duid.duid, client->duid.size) != 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "The client ID in %s message does not match. Ignoring.",
                                              dhcp6_message_type_to_string(message->type));

        if (client->state == DHCP6_STATE_INFORMATION_REQUEST) {
                client->information_refresh_time_usec = MAX(irt, IRT_MINIMUM);
                log_dhcp6_client(client, "New information request will be refused in %s.",
                                 FORMAT_TIMESPAN(client->information_refresh_time_usec, USEC_PER_SEC));

        } else {
                r = dhcp6_lease_get_serverid(lease, NULL, NULL);
                if (r < 0)
                        return log_dhcp6_client_errno(client, r, "%s has no server id",
                                                      dhcp6_message_type_to_string(message->type));

                if (!lease->ia_na && !lease->ia_pd)
                        return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                                      "No IA_PD prefix or IA_NA address received. Ignoring.");

                dhcp6_lease_set_lifetime(lease);
        }

        return 0;
}

static sd_dhcp6_lease *dhcp6_lease_free(sd_dhcp6_lease *lease) {
        if (!lease)
                return NULL;

        set_free(lease->vendor_options);
        free(lease->sorted_vendor_options);
        free(lease->clientid);
        free(lease->serverid);
        dhcp6_ia_free(lease->ia_na);
        dhcp6_ia_free(lease->ia_pd);
        free(lease->dns);
        dns_resolver_done_many(lease->dnr, lease->n_dnr);
        free(lease->fqdn);
        free(lease->captive_portal);
        strv_free(lease->domains);
        free(lease->ntp);
        strv_free(lease->ntp_fqdn);
        free(lease->sntp);

        return mfree(lease);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_lease, sd_dhcp6_lease, dhcp6_lease_free);

int dhcp6_lease_new(sd_dhcp6_lease **ret) {
        sd_dhcp6_lease *lease;

        assert(ret);

        lease = new(sd_dhcp6_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp6_lease) {
                .n_ref = 1,
        };

        *ret = lease;
        return 0;
}

int dhcp6_lease_new_from_message(
                sd_dhcp6_client *client,
                const DHCP6Message *message,
                size_t len,
                const triple_timestamp *timestamp,
                const struct in6_addr *server_address,
                sd_dhcp6_lease **ret) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        int r;

        assert(client);
        assert(message);
        assert(len >= sizeof(DHCP6Message));
        assert(ret);

        r = dhcp6_lease_new(&lease);
        if (r < 0)
                return r;

        dhcp6_lease_set_timestamp(lease, timestamp);
        dhcp6_lease_set_server_address(lease, server_address);

        r = dhcp6_lease_parse_message(client, lease, message, len);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(lease);
        return 0;
}
