/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "condition.h"
#include "conf-parser.h"
#include "dhcp-lease-internal.h"
#include "ether-addr-util.h"
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

const char *net_get_name(struct udev_device *device) {
        const char *name, *field;

        assert(device);

        /* fetch some persistent data unique (on this machine) to this device */
        FOREACH_STRING(field, "ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC") {
                name = udev_device_get_property_value(device, field);
                if (name)
                        return name;
        }

        return NULL;
}

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,fa,90,fe,4b,4c,9d,af,d5,d7,a1,b1,2e,8a)

int net_get_unique_predictable_data(struct udev_device *device, uint64_t *result) {
        size_t l, sz = 0;
        const char *name = NULL;
        int r;
        uint8_t *v;

        assert(device);

        name = net_get_name(device);
        if (!name)
                return -ENOENT;

        l = strlen(name);
        sz = sizeof(sd_id128_t) + l;
        v = alloca(sz);

        /* fetch some persistent data unique to this machine */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                 return r;
        memcpy(v + sizeof(sd_id128_t), name, l);

        /* Let's hash the machine ID plus the device name. We
        * use a fixed, but originally randomly created hash
        * key here. */
        *result = htole64(siphash24(v, sz, HASH_KEY.bytes));

        return 0;
}

bool net_match_config(const struct ether_addr *match_mac,
                      char * const *match_paths,
                      char * const *match_drivers,
                      char * const *match_types,
                      char * const *match_names,
                      Condition *match_host,
                      Condition *match_virt,
                      Condition *match_kernel,
                      Condition *match_arch,
                      const struct ether_addr *dev_mac,
                      const char *dev_path,
                      const char *dev_parent_driver,
                      const char *dev_driver,
                      const char *dev_type,
                      const char *dev_name) {

        if (match_host && !condition_test(match_host))
                return false;

        if (match_virt && !condition_test(match_virt))
                return false;

        if (match_kernel && !condition_test(match_kernel))
                return false;

        if (match_arch && !condition_test(match_arch))
                return false;

        if (match_mac && (!dev_mac || memcmp(match_mac, dev_mac, ETH_ALEN)))
                return false;

        if (!strv_isempty(match_paths) &&
            (!dev_path || !strv_fnmatch(match_paths, dev_path, 0)))
                return false;

        if (!strv_isempty(match_drivers) &&
            (!dev_driver || !strv_fnmatch(match_drivers, dev_driver, 0)))
                return false;

        if (!strv_isempty(match_types) &&
            (!dev_type || !strv_fnmatch_or_empty(match_types, dev_type, 0)))
                return false;

        if (!strv_isempty(match_names) &&
            (!dev_name || !strv_fnmatch_or_empty(match_names, dev_name, 0)))
                return false;

        return true;
}

int config_parse_net_condition(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata) {

        ConditionType cond = ltype;
        Condition **ret = data;
        bool negate;
        Condition *c;
        _cleanup_free_ char *s = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        s = strdup(rvalue);
        if (!s)
                return log_oom();

        c = condition_new(cond, s, false, negate);
        if (!c)
                return log_oom();

        if (*ret)
                condition_free(*ret);

        *ret = c;
        return 0;
}

int config_parse_ifnames(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***sv = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&rvalue, &word, NULL, 0);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse interface name list: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                if (!ifname_valid(word)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Interface name is not valid or too long, ignoring assignment: %s", rvalue);
                        return 0;
                }

                r = strv_push(sv, word);
                if (r < 0)
                        return log_oom();

                word = NULL;
        }

        return 0;
}

int config_parse_ifalias(const char *unit,
                         const char *filename,
                         unsigned line,
                         const char *section,
                         unsigned section_line,
                         const char *lvalue,
                         int ltype,
                         const char *rvalue,
                         void *data,
                         void *userdata) {

        char **s = data;
        _cleanup_free_ char *n = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        if (!ascii_is_valid(n) || strlen(n) >= IFALIASZ) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Interface alias is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        free(*s);
        if (*n) {
                *s = n;
                n = NULL;
        } else
                *s = NULL;

        return 0;
}

int config_parse_hwaddr(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata) {
        struct ether_addr **hwaddr = data;
        struct ether_addr *n;
        const char *start;
        size_t offset;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = new0(struct ether_addr, 1);
        if (!n)
                return log_oom();

        start = rvalue + strspn(rvalue, WHITESPACE);
        r = ether_addr_from_string(start, n, &offset);

        if (r || (start[offset + strspn(start + offset, WHITESPACE)] != '\0')) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Not a valid MAC address, ignoring assignment: %s", rvalue);
                free(n);
                return 0;
        }

        free(*hwaddr);
        *hwaddr = n;

        return 0;
}

int config_parse_iaid(const char *unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {
        uint32_t iaid;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &iaid);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Unable to read IAID, ignoring assignment: %s", rvalue);
                return 0;
        }

        *((uint32_t *)data) = iaid;

        return 0;
}

void serialize_in_addrs(FILE *f, const struct in_addr *addresses, size_t size) {
        unsigned i;

        assert(f);
        assert(addresses);
        assert(size);

        for (i = 0; i < size; i++)
                fprintf(f, "%s%s", inet_ntoa(addresses[i]),
                        (i < (size - 1)) ? " ": "");
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

                new_addresses = realloc(addresses, (size + 1) * sizeof(struct in_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                r = inet_pton(AF_INET, word, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
        }

        *ret = addresses;
        addresses = NULL;

        return size;
}

void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses,
                         size_t size) {
        unsigned i;

        assert(f);
        assert(addresses);
        assert(size);

        for (i = 0; i < size; i++)
                fprintf(f, SD_NDISC_ADDRESS_FORMAT_STR"%s",
                        SD_NDISC_ADDRESS_FORMAT_VAL(addresses[i]),
                        (i < (size - 1)) ? " ": "");
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

                new_addresses = realloc(addresses, (size + 1) * sizeof(struct in6_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                r = inet_pton(AF_INET6, word, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
        }

        *ret = addresses;
        addresses = NULL;

        return size;
}

void serialize_dhcp_routes(FILE *f, const char *key, sd_dhcp_route **routes, size_t size) {
        unsigned i;

        assert(f);
        assert(key);
        assert(routes);
        assert(size);

        fprintf(f, "%s=", key);

        for (i = 0; i < size; i++) {
                struct in_addr dest, gw;
                uint8_t length;

                assert_se(sd_dhcp_route_get_destination(routes[i], &dest) >= 0);
                assert_se(sd_dhcp_route_get_gateway(routes[i], &gw) >= 0);
                assert_se(sd_dhcp_route_get_destination_prefix_length(routes[i], &length) >= 0);

                fprintf(f, "%s/%" PRIu8, inet_ntoa(dest), length);
                fprintf(f, ",%s%s", inet_ntoa(gw), (i < (size - 1)) ? " ": "");
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
        *ret = routes;
        routes = NULL;

        return 0;
}

int serialize_dhcp_option(FILE *f, const char *key, const void *data, size_t size) {
        _cleanup_free_ char *hex_buf = NULL;

        assert(f);
        assert(key);
        assert(data);

        hex_buf = hexmem(data, size);
        if (hex_buf == NULL)
                return -ENOMEM;

        fprintf(f, "%s=%s\n", key, hex_buf);

        return 0;
}

int deserialize_dhcp_option(void **data, size_t *data_len, const char *string) {
        assert(data);
        assert(data_len);
        assert(string);

        if (strlen(string) % 2)
                return -EINVAL;

        return unhexmem(string, strlen(string), (void **)data, data_len);
}
