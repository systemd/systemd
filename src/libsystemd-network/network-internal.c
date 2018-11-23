/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/ether.h>

#include "sd-id128.h"
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

const char *net_get_name(sd_device *device) {
        const char *name, *field;

        assert(device);

        /* fetch some persistent data unique (on this machine) to this device */
        FOREACH_STRING(field, "ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH", "ID_NET_NAME_MAC")
                if (sd_device_get_property_value(device, field, &name) >= 0)
                        return name;

        return NULL;
}

#define HASH_KEY SD_ID128_MAKE(d3,1e,48,fa,90,fe,4b,4c,9d,af,d5,d7,a1,b1,2e,8a)

int net_get_unique_predictable_data(sd_device *device, uint64_t *result) {
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

static bool net_condition_test_strv(char * const *raw_patterns,
                                    const char *string) {
        if (strv_isempty(raw_patterns))
                return true;

        /* If the patterns begin with "!", edit it out and negate the test. */
        if (raw_patterns[0][0] == '!') {
                char **patterns;
                size_t i, length;

                length = strv_length(raw_patterns) + 1; /* Include the NULL. */
                patterns = newa(char*, length);
                patterns[0] = raw_patterns[0] + 1; /* Skip the "!". */
                for (i = 1; i < length; i++)
                        patterns[i] = raw_patterns[i];

                return !string || !strv_fnmatch(patterns, string, 0);
        }

        return string && strv_fnmatch(raw_patterns, string, 0);
}

bool net_match_config(Set *match_mac,
                      char * const *match_paths,
                      char * const *match_drivers,
                      char * const *match_types,
                      char * const *match_names,
                      Condition *match_host,
                      Condition *match_virt,
                      Condition *match_kernel_cmdline,
                      Condition *match_kernel_version,
                      Condition *match_arch,
                      const struct ether_addr *dev_mac,
                      const char *dev_path,
                      const char *dev_parent_driver,
                      const char *dev_driver,
                      const char *dev_type,
                      const char *dev_name) {

        if (match_host && condition_test(match_host) <= 0)
                return false;

        if (match_virt && condition_test(match_virt) <= 0)
                return false;

        if (match_kernel_cmdline && condition_test(match_kernel_cmdline) <= 0)
                return false;

        if (match_kernel_version && condition_test(match_kernel_version) <= 0)
                return false;

        if (match_arch && condition_test(match_arch) <= 0)
                return false;

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

        *ret = TAKE_PTR(addresses);

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
        *ret = TAKE_PTR(routes);

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
