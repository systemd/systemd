/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "dhcp-lease-internal.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "log.h"
#include "network-internal.h"
#include "parse-util.h"
#include "strv.h"

size_t serialize_in_addrs(FILE *f,
                          const struct in_addr *addresses,
                          size_t size,
                          bool *with_leading_space,
                          bool (*predicate)(const struct in_addr *addr)) {
        assert(f);
        assert(addresses);

        size_t count = 0;
        bool _space = false;
        if (!with_leading_space)
                with_leading_space = &_space;

        for (size_t i = 0; i < size; i++) {
                if (predicate && !predicate(&addresses[i]))
                        continue;

                if (*with_leading_space)
                        fputc(' ', f);
                fputs(IN4_ADDR_TO_STRING(&addresses[i]), f);
                count++;
                *with_leading_space = true;
        }

        return count;
}

int deserialize_in_addrs(struct in_addr **ret, const char *string) {
        _cleanup_free_ struct in_addr *addresses = NULL;
        int size = 0;

        assert(ret);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                union in_addr_union a;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (in_addr_from_string(AF_INET, word, &a) < 0)
                        continue;

                if (!GREEDY_REALLOC(addresses, size + 1))
                        return -ENOMEM;

                addresses[size++] = a.in;
        }

        *ret = size > 0 ? TAKE_PTR(addresses) : NULL;

        return size;
}

void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses, size_t size, bool *with_leading_space) {
        assert(f);
        assert(addresses);
        assert(size);

        bool _space = false;
        if (!with_leading_space)
                with_leading_space = &_space;

        for (size_t i = 0; i < size; i++) {
                if (*with_leading_space)
                        fputc(' ', f);
                fputs(IN6_ADDR_TO_STRING(&addresses[i]), f);
                *with_leading_space = true;
        }
}

int deserialize_in6_addrs(struct in6_addr **ret, const char *string) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        int size = 0;

        assert(ret);
        assert(string);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                union in_addr_union a;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (in_addr_from_string(AF_INET6, word, &a) < 0)
                        continue;

                if (!GREEDY_REALLOC(addresses, size + 1))
                        return -ENOMEM;

                addresses[size++] = a.in6;
        }

        *ret = TAKE_PTR(addresses);

        return size;
}

int serialize_dnr(FILE *f, const sd_dns_resolver *dnr, size_t n_dnr, bool *with_leading_space) {
        int r;

        bool _space = false;
        if (!with_leading_space)
                with_leading_space = &_space;

        int n = 0;
        _cleanup_strv_free_ char **names = NULL;
        r = dns_resolvers_to_dot_strv(dnr, n_dnr, &names);
        if (r < 0)
                return r;
        if (r > 0)
                fputstrv(f, names, NULL, with_leading_space);
        n += r;
        return n;
}

static int coalesce_dnr(sd_dns_resolver *dnr, size_t n_dnr, int family, const char *auth_name,
                union in_addr_union *addr) {
        assert(dnr || n_dnr == 0);
        assert(auth_name);
        assert(addr);

        /* Look through list of DNR for matching resolvers to add our addr to. Since DoT is assumed, no need
         * to compare transports/dohpath/etc. */
        FOREACH_ARRAY(res, dnr, n_dnr) {
                if (family == res->family && streq(auth_name, res->auth_name)) {
                        if (!GREEDY_REALLOC(res->addrs, res->n_addrs + 1))
                                return -ENOMEM;
                        res->addrs[res->n_addrs++] = *addr;
                        return true;
                }
        }

        return false;
}

/* Deserialized resolvers are assumed to offer DoT service. */
int deserialize_dnr(sd_dns_resolver **ret, const char *string) {
        int r;

        assert(ret);
        assert(string);

        sd_dns_resolver *dnr = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(dnr, n, dns_resolver_done_many);
        int priority = 0;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                uint16_t port;
                int family;
                _cleanup_free_ union in_addr_union *addr = new(union in_addr_union, 1);
                _cleanup_free_ char *auth_name = NULL;

                r = in_addr_port_ifindex_name_from_string_auto(word, &family, addr, &port, NULL, &auth_name);
                if (r < 0)
                        return r;

                r = coalesce_dnr(dnr, n, family, auth_name, addr);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                if (!GREEDY_REALLOC(dnr, n+1))
                        return -ENOMEM;

                priority = n+1;
                dnr[n++] = (sd_dns_resolver) {
                        .priority = priority, /* not serialized, but this will preserve the order */
                        .auth_name = TAKE_PTR(auth_name),
                        .family = family,
                        .addrs = TAKE_PTR(addr),
                        .n_addrs = 1,
                        .transports = SD_DNS_ALPN_DOT,
                        .port = port,
                };
        }

        *ret = TAKE_PTR(dnr);
        return n;
}

void serialize_dhcp_routes(FILE *f, const char *key, sd_dhcp_route **routes, size_t size) {
        assert(f);
        assert(key);
        assert(routes);
        assert(size);

        fprintf(f, "%s=", key);

        for (size_t i = 0; i < size; i++) {
                struct in_addr dest, gw;
                uint8_t length;

                assert_se(sd_dhcp_route_get_destination(routes[i], &dest) >= 0);
                assert_se(sd_dhcp_route_get_gateway(routes[i], &gw) >= 0);
                assert_se(sd_dhcp_route_get_destination_prefix_length(routes[i], &length) >= 0);

                fprintf(f, "%s,%s%s",
                        IN4_ADDR_PREFIX_TO_STRING(&dest, length),
                        IN4_ADDR_TO_STRING(&gw),
                        i < size - 1 ? " ": "");
        }

        fputs("\n", f);
}

int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, const char *string) {
        _cleanup_free_ struct sd_dhcp_route *routes = NULL;
        size_t size = 0;

        assert(ret);
        assert(ret_size);
        assert(string);

         /* WORD FORMAT: dst_ip/dst_prefixlen,gw_ip */
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *tok, *tok_end;
                unsigned n;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!GREEDY_REALLOC(routes, size + 1))
                        return -ENOMEM;

                tok = word;

                /* get the subnet */
                tok_end = strchr(tok, '/');
                if (!tok_end)
                        continue;
                *tok_end = '\0';

                r = inet_aton(tok, &routes[size].dst_addr);
                if (r == 0)
                        continue;

                tok = tok_end + 1;

                /* get the prefixlen */
                tok_end = strchr(tok, ',');
                if (!tok_end)
                        continue;

                *tok_end = '\0';

                r = safe_atou(tok, &n);
                if (r < 0 || n > 32)
                        continue;

                routes[size].dst_prefixlen = (uint8_t) n;
                tok = tok_end + 1;

                /* get the gateway */
                r = inet_aton(tok, &routes[size].gw_addr);
                if (r == 0)
                        continue;

                size++;
        }

        *ret_size = size;
        *ret = TAKE_PTR(routes);

        return 0;
}

int serialize_dhcp_option(FILE *f, const char *key, const void *data, size_t size) {
        _cleanup_free_ char *hex_buf = NULL;

        assert(f);
        assert(key);
        assert(data);

        hex_buf = hexmem(data, size);
        if (!hex_buf)
                return -ENOMEM;

        fprintf(f, "%s=%s\n", key, hex_buf);

        return 0;
}
