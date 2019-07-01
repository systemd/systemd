/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "sd-id128.h"
#include "sd-ndisc.h"

#include "alloc-util.h"
#include "condition.h"
#include "conf-parser.h"
#include "device-util.h"
#include "dhcp-lease-internal.h"
#include "env-util.h"
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

static bool net_condition_test_strv(char * const *patterns, const char *string) {
        char * const *p;
        bool match = false, has_positive_rule = false;

        if (strv_isempty(patterns))
                return true;

        STRV_FOREACH(p, patterns) {
                const char *q = *p;
                bool invert;

                invert = *q == '!';
                q += invert;

                if (!invert)
                        has_positive_rule = true;

                if (string && fnmatch(q, string, 0) == 0) {
                        if (invert)
                                return false;
                        else
                                match = true;
                }
        }

        return has_positive_rule ? match : true;
}

static int net_condition_test_property(char * const *match_property, sd_device *device) {
        char * const *p;

        if (strv_isempty(match_property))
                return true;

        STRV_FOREACH(p, match_property) {
                _cleanup_free_ char *key = NULL;
                const char *val, *dev_val;
                bool invert, v;

                invert = **p == '!';

                val = strchr(*p + invert, '=');
                if (!val)
                        return -EINVAL;

                key = strndup(*p + invert, val - *p - invert);
                if (!key)
                        return -ENOMEM;

                val++;

                v = device &&
                        sd_device_get_property_value(device, key, &dev_val) >= 0 &&
                        fnmatch(val, dev_val, 0) == 0;

                if (invert ? v : !v)
                        return false;
        }

        return true;
}

bool net_match_config(Set *match_mac,
                      char * const *match_paths,
                      char * const *match_drivers,
                      char * const *match_types,
                      char * const *match_names,
                      char * const *match_property,
                      sd_device *device,
                      const struct ether_addr *dev_mac,
                      const char *dev_name) {

        const char *dev_path = NULL, *dev_driver = NULL, *dev_type = NULL, *mac_str;

        if (device) {
                (void) sd_device_get_property_value(device, "ID_PATH", &dev_path);
                (void) sd_device_get_property_value(device, "ID_NET_DRIVER", &dev_driver);
                (void) sd_device_get_devtype(device, &dev_type);

                if (!dev_name)
                        (void) sd_device_get_sysname(device, &dev_name);
                if (!dev_mac &&
                    sd_device_get_sysattr_value(device, "address", &mac_str) >= 0)
                        dev_mac = ether_aton(mac_str);
        }

        if (match_mac && (!dev_mac || !set_contains(match_mac, dev_mac)))
                return false;

        if (!net_condition_test_strv(match_paths, dev_path))
                return false;

        if (!net_condition_test_strv(match_drivers, dev_driver))
                return false;

        if (!net_condition_test_strv(match_types, dev_type))
                return false;

        if (!net_condition_test_strv(match_names, dev_name))
                return false;

        if (!net_condition_test_property(match_property, device))
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
        Condition **list = data, *c;
        bool negate;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *list = condition_free_list_type(*list, cond);
                return 0;
        }

        negate = rvalue[0] == '!';
        if (negate)
                rvalue++;

        c = condition_new(cond, rvalue, false, negate);
        if (!c)
                return log_oom();

        /* Drop previous assignment. */
        *list = condition_free_list_type(*list, cond);

        LIST_PREPEND(conditions, *list, c);
        return 0;
}

int config_parse_match_strv(
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

        const char *p = rvalue;
        char ***sv = data;
        bool invert;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 0;
        }

        invert = *p == '!';
        p += invert;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (invert) {
                        k = strjoin("!", word);
                        if (!k)
                                return log_oom();
                } else
                        k = TAKE_PTR(word);

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_match_ifnames(
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

        const char *p = rvalue;
        char ***sv = data;
        bool invert;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        invert = *p == '!';
        p += invert;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Failed to parse interface name list: %s", rvalue);
                        return 0;
                }

                if (!ifname_valid(word)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Interface name is not valid or too long, ignoring assignment: %s", word);
                        continue;
                }

                if (invert) {
                        k = strjoin("!", word);
                        if (!k)
                                return log_oom();
                } else
                        k = TAKE_PTR(word);

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_match_property(
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

        const char *p = rvalue;
        char ***sv = data;
        bool invert;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        invert = *p == '!';
        p += invert;

        for (;;) {
                _cleanup_free_ char *word = NULL, *k = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                if (!env_assignment_is_valid(word)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid property or value, ignoring assignment: %s", word);
                        continue;
                }

                if (invert) {
                        k = strjoin("!", word);
                        if (!k)
                                return log_oom();
                } else
                        k = TAKE_PTR(word);

                r = strv_consume(sv, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }
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

        if (isempty(n))
                *s = mfree(*s);
        else
                free_and_replace(*s, n);

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

        _cleanup_free_ struct ether_addr *n = NULL;
        struct ether_addr **hwaddr = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = new0(struct ether_addr, 1);
        if (!n)
                return log_oom();

        r = ether_addr_from_string(rvalue, n);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Not a valid MAC address, ignoring assignment: %s", rvalue);
                return 0;
        }

        free_and_replace(*hwaddr, n);

        return 0;
}

int config_parse_hwaddrs(const char *unit,
                         const char *filename,
                         unsigned line,
                         const char *section,
                         unsigned section_line,
                         const char *lvalue,
                         int ltype,
                         const char *rvalue,
                         void *data,
                         void *userdata) {

        _cleanup_set_free_free_ Set *s = NULL;
        const char *p = rvalue;
        Set **hwaddrs = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *hwaddrs = set_free_free(*hwaddrs);
                return 0;
        }

        s = set_new(&ether_addr_hash_ops);
        if (!s)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL;
                _cleanup_free_ struct ether_addr *n = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                n = new(struct ether_addr, 1);
                if (!n)
                        return log_oom();

                r = ether_addr_from_string(word, n);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Not a valid MAC address, ignoring: %s", word);
                        continue;
                }

                r = set_put(s, n);
                if (r < 0)
                        return log_oom();
                if (r > 0)
                        n = NULL; /* avoid cleanup */
        }

        r = set_ensure_allocated(hwaddrs, &ether_addr_hash_ops);
        if (r < 0)
                return log_oom();

        r = set_move(*hwaddrs, s);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_bridge_port_priority(
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

        uint16_t i;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou16(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse bridge port priority, ignoring: %s", rvalue);
                return 0;
        }

        if (i > LINK_BRIDGE_PORT_PRIORITY_MAX) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Bridge port priority is larger than maximum %u, ignoring: %s", LINK_BRIDGE_PORT_PRIORITY_MAX, rvalue);
                return 0;
        }

        *((uint16_t *)data) = i;

        return 0;
}

size_t serialize_in_addrs(FILE *f,
                          const struct in_addr *addresses,
                          size_t size,
                          bool with_leading_space,
                          bool (*predicate)(const struct in_addr *addr)) {
        size_t count;
        size_t i;

        assert(f);
        assert(addresses);

        count = 0;

        for (i = 0; i < size; i++) {
                char sbuf[INET_ADDRSTRLEN];

                if (predicate && !predicate(&addresses[i]))
                        continue;
                if (with_leading_space)
                        fputc(' ', f);
                else
                        with_leading_space = true;
                fputs(inet_ntop(AF_INET, &addresses[i], sbuf, sizeof(sbuf)), f);
                count++;
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

void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses, size_t size) {
        unsigned i;

        assert(f);
        assert(addresses);
        assert(size);

        for (i = 0; i < size; i++) {
                char buffer[INET6_ADDRSTRLEN];

                fputs(inet_ntop(AF_INET6, addresses+i, buffer, sizeof(buffer)), f);

                if (i < size - 1)
                        fputc(' ', f);
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
        unsigned i;

        assert(f);
        assert(key);
        assert(routes);
        assert(size);

        fprintf(f, "%s=", key);

        for (i = 0; i < size; i++) {
                char sbuf[INET_ADDRSTRLEN];
                struct in_addr dest, gw;
                uint8_t length;

                assert_se(sd_dhcp_route_get_destination(routes[i], &dest) >= 0);
                assert_se(sd_dhcp_route_get_gateway(routes[i], &gw) >= 0);
                assert_se(sd_dhcp_route_get_destination_prefix_length(routes[i], &length) >= 0);

                fprintf(f, "%s/%" PRIu8, inet_ntop(AF_INET, &dest, sbuf, sizeof(sbuf)), length);
                fprintf(f, ",%s%s", inet_ntop(AF_INET, &gw, sbuf, sizeof(sbuf)), (i < (size - 1)) ? " ": "");
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
