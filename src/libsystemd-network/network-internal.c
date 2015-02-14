/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <netinet/ether.h>
#include <linux/if.h>
#include <arpa/inet.h>

#include "strv.h"
#include "siphash24.h"
#include "dhcp-lease-internal.h"
#include "log.h"
#include "utf8.h"
#include "util.h"
#include "conf-parser.h"
#include "condition.h"
#include "network-internal.h"

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

int net_get_unique_predictable_data(struct udev_device *device, uint8_t result[8]) {
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
        siphash24(result, v, sz, HASH_KEY.bytes);

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

int config_parse_ifname(const char *unit,
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

        if (!ascii_is_valid(n) || strlen(n) >= IFNAMSIZ) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Interface name is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
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

int config_parse_ifnames(const char *unit,
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
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(word, l, rvalue, state) {
                char *n;

                n = strndup(word, l);
                if (!n)
                        return log_oom();

                if (!ascii_is_valid(n) || strlen(n) >= IFNAMSIZ) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Interface name is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
                        free(n);
                        return 0;
                }

                r = strv_consume(sv, n);
                if (r < 0)
                        return log_oom();
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
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Interface alias is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
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
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = new0(struct ether_addr, 1);
        if (!n)
                return log_oom();

        r = sscanf(rvalue, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                   &n->ether_addr_octet[0],
                   &n->ether_addr_octet[1],
                   &n->ether_addr_octet[2],
                   &n->ether_addr_octet[3],
                   &n->ether_addr_octet[4],
                   &n->ether_addr_octet[5]);
        if (r != 6) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Not a valid MAC address, ignoring assignment: %s", rvalue);
                free(n);
                return 0;
        }

        free(*hwaddr);
        *hwaddr = n;

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
        const char *word, *state;
        size_t len;

        assert(ret);
        assert(string);

        FOREACH_WORD(word, len, string, state) {
                _cleanup_free_ char *addr_str = NULL;
                struct in_addr *new_addresses;
                int r;

                new_addresses = realloc(addresses, (size + 1) * sizeof(struct in_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                addr_str = strndup(word, len);
                if (!addr_str)
                        return -ENOMEM;

                r = inet_pton(AF_INET, addr_str, &(addresses[size]));
                if (r <= 0)
                        continue;

                size ++;
        }

        *ret = addresses;
        addresses = NULL;

        return size;
}

int deserialize_in6_addrs(struct in6_addr **ret, const char *string) {
        _cleanup_free_ struct in6_addr *addresses = NULL;
        int size = 0;
        const char *word, *state;
        size_t len;

        assert(ret);
        assert(string);

        FOREACH_WORD(word, len, string, state) {
                _cleanup_free_ char *addr_str = NULL;
                struct in6_addr *new_addresses;
                int r;

                new_addresses = realloc(addresses, (size + 1) * sizeof(struct in6_addr));
                if (!new_addresses)
                        return -ENOMEM;
                else
                        addresses = new_addresses;

                addr_str = strndup(word, len);
                if (!addr_str)
                        return -ENOMEM;

                r = inet_pton(AF_INET6, addr_str, &(addresses[size]));
                if (r <= 0)
                        continue;

                size++;
        }

        *ret = addresses;
        addresses = NULL;

        return size;
}

void serialize_dhcp_routes(FILE *f, const char *key, struct sd_dhcp_route *routes, size_t size) {
        unsigned i;

        assert(f);
        assert(key);
        assert(routes);
        assert(size);

        fprintf(f, "%s=", key);

        for (i = 0; i < size; i++) {
                fprintf(f, "%s/%" PRIu8, inet_ntoa(routes[i].dst_addr),
                        routes[i].dst_prefixlen);
                fprintf(f, ",%s%s", inet_ntoa(routes[i].gw_addr),
                        (i < (size - 1)) ? " ": "");
        }

        fputs("\n", f);
}

int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, size_t *ret_allocated, const char *string) {
        _cleanup_free_ struct sd_dhcp_route *routes = NULL;
        size_t size = 0, allocated = 0;
        const char *word, *state;
        size_t len;

        assert(ret);
        assert(ret_size);
        assert(ret_allocated);
        assert(string);

        FOREACH_WORD(word, len, string, state) {
                /* WORD FORMAT: dst_ip/dst_prefixlen,gw_ip */
                _cleanup_free_ char* entry = NULL;
                char *tok, *tok_end;
                unsigned n;
                int r;

                if (!GREEDY_REALLOC(routes, allocated, size + 1))
                        return -ENOMEM;

                entry = strndup(word, len);
                if(!entry)
                        return -ENOMEM;

                tok = entry;

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
