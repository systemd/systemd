/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <linux/if.h>

#include "sd-id128.h"
#include "sd-ndisc.h"

#include "alloc-util.h"
#include "device-util.h"
#include "dhcp-lease-internal.h"
#include "hexdecoct.h"
#include "log.h"
#include "network-internal.h"
#include "parse-util.h"
#include "siphash24.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "util.h"

const char *net_get_name_persistent(sd_device *device) {
        const char *name, *field;

        assert(device);

        /* fetch some persistent data unique (on this machine) to this device */
        FOREACH_STRING(field, "ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC")
                if (sd_device_get_property_value(device, field, &name) >= 0)
                        return name;

        return NULL;
}

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,fa,90,fe,4b,4c,9d,af,d5,d7,a1,b1,2e,8a)

int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *result) {
        size_t l, sz = 0;
        const char *name;
        int r;
        uint8_t *v;

        assert(device);

        /* net_get_name_persistent() will return one of the device names based on stable information about
         * the device. If this is not available, we fall back to using the actual device name. */
        name = net_get_name_persistent(device);
        if (!name && use_sysname)
                (void) sd_device_get_sysname(device, &name);
        if (!name)
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(ENODATA),
                                              "No stable identifying information found");

        log_device_debug(device, "Using \"%s\" as stable identifying information", name);
        l = strlen(name);
        sz = sizeof(sd_id128_t) + l;
        v = newa(uint8_t, sz);

        /* Fetch some persistent data unique to this machine */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                 return r;
        memcpy(v + sizeof(sd_id128_t), name, l);

        /* Let's hash the machine ID plus the device name. We use
         * a fixed, but originally randomly created hash key here. */
        *result = htole64(siphash24(v, sz, HASH_KEY.bytes));
        return 0;
}

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
                char sbuf[INET_ADDRSTRLEN];

                if (predicate && !predicate(&addresses[i]))
                        continue;

                if (*with_leading_space)
                        fputc(' ', f);
                fputs(inet_ntop(AF_INET, &addresses[i], sbuf, sizeof(sbuf)), f);
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
                struct in_addr *new_addresses;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                new_addresses = reallocarray(addresses, size + 1, sizeof(struct in_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                r = inet_pton(AF_INET, word, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
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
                char buffer[INET6_ADDRSTRLEN];

                if (*with_leading_space)
                        fputc(' ', f);
                fputs(inet_ntop(AF_INET6, addresses+i, buffer, sizeof(buffer)), f);
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
                struct in6_addr *new_addresses;
                int r;

                r = extract_first_word(&string, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                new_addresses = reallocarray(addresses, size + 1, sizeof(struct in6_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                r = inet_pton(AF_INET6, word, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
        }

        *ret = TAKE_PTR(addresses);

        return size;
}

void serialize_dhcp_routes(FILE *f, const char *key, sd_dhcp_route **routes, size_t size) {
        assert(f);
        assert(key);
        assert(routes);
        assert(size);

        fprintf(f, "%s=", key);

        for (size_t i = 0; i < size; i++) {
                char sbuf[INET_ADDRSTRLEN];
                struct in_addr dest, gw;
                uint8_t length;

                assert_se(sd_dhcp_route_get_destination(routes[i], &dest) >= 0);
                assert_se(sd_dhcp_route_get_gateway(routes[i], &gw) >= 0);
                assert_se(sd_dhcp_route_get_destination_prefix_length(routes[i], &length) >= 0);

                fprintf(f, "%s/%" PRIu8, inet_ntop(AF_INET, &dest, sbuf, sizeof sbuf), length);
                fprintf(f, ",%s%s", inet_ntop(AF_INET, &gw, sbuf, sizeof sbuf), i < size - 1 ? " ": "");
        }

        fputs("\n", f);
}

int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, size_t *ret_allocated, const char *string) {
        _cleanup_free_ struct sd_dhcp_route *routes = NULL;
        size_t size = 0, allocated = 0;

        assert(ret);
        assert(ret_size);
        assert(ret_allocated);
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

                if (!GREEDY_REALLOC(routes, allocated, size + 1))
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
        *ret_allocated = allocated;
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
