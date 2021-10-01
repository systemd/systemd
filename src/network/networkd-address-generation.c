/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-id128.h"

#include "memory-util.h"
#include "networkd-address-generation.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "string-util.h"

#define DAD_CONFLICTS_IDGEN_RETRIES_RFC7217 3

/* https://tools.ietf.org/html/rfc5453 */
/* https://www.iana.org/assignments/ipv6-interface-ids/ipv6-interface-ids.xml */

#define SUBNET_ROUTER_ANYCAST_ADDRESS_RFC4291               ((struct in6_addr) { .s6_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } })
#define SUBNET_ROUTER_ANYCAST_PREFIXLEN                     8
#define RESERVED_IPV6_INTERFACE_IDENTIFIERS_ADDRESS_RFC4291 ((struct in6_addr) { .s6_addr = { 0x02, 0x00, 0x5E, 0xFF, 0xFE } })
#define RESERVED_IPV6_INTERFACE_IDENTIFIERS_PREFIXLEN       5
#define RESERVED_SUBNET_ANYCAST_ADDRESSES_RFC4291           ((struct in6_addr) { .s6_addr = { 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } })
#define RESERVED_SUBNET_ANYCAST_PREFIXLEN                   7

#define NDISC_APP_ID   SD_ID128_MAKE(13,ac,81,a7,d5,3f,49,78,92,79,5d,0c,29,3a,bc,7e)

typedef enum IPv6TokenAddressGeneration {
        IPV6_TOKEN_ADDRESS_GENERATION_NONE,
        IPV6_TOKEN_ADDRESS_GENERATION_STATIC,
        IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE,
        _IPV6_TOKEN_ADDRESS_GENERATION_MAX,
        _IPV6_TOKEN_ADDRESS_GENERATION_INVALID = -EINVAL,
} IPv6TokenAddressGeneration;

typedef struct IPv6Token {
        IPv6TokenAddressGeneration address_generation_type;

        uint8_t dad_counter;
        struct in6_addr prefix;
} IPv6Token;

int generate_ipv6_eui_64_address(const Link *link, struct in6_addr *ret) {
        assert(link);
        assert(ret);

        if (link->iftype == ARPHRD_INFINIBAND) {
                /* see RFC4391 section 8 */
                memcpy(&ret->s6_addr[8], &link->hw_addr.infiniband[12], 8);
                ret->s6_addr[8] ^= 1 << 1;

                return 0;
        }

        /* see RFC4291 section 2.5.1 */
        ret->s6_addr[8]  = link->hw_addr.ether.ether_addr_octet[0];
        ret->s6_addr[8] ^= 1 << 1;
        ret->s6_addr[9]  = link->hw_addr.ether.ether_addr_octet[1];
        ret->s6_addr[10] = link->hw_addr.ether.ether_addr_octet[2];
        ret->s6_addr[11] = 0xff;
        ret->s6_addr[12] = 0xfe;
        ret->s6_addr[13] = link->hw_addr.ether.ether_addr_octet[3];
        ret->s6_addr[14] = link->hw_addr.ether.ether_addr_octet[4];
        ret->s6_addr[15] = link->hw_addr.ether.ether_addr_octet[5];

        return 0;
}

static bool stable_private_address_is_valid(const struct in6_addr *addr) {
        assert(addr);

        /* According to rfc4291, generated address should not be in the following ranges. */

        if (memcmp(addr, &SUBNET_ROUTER_ANYCAST_ADDRESS_RFC4291, SUBNET_ROUTER_ANYCAST_PREFIXLEN) == 0)
                return false;

        if (memcmp(addr, &RESERVED_IPV6_INTERFACE_IDENTIFIERS_ADDRESS_RFC4291, RESERVED_IPV6_INTERFACE_IDENTIFIERS_PREFIXLEN) == 0)
                return false;

        if (memcmp(addr, &RESERVED_SUBNET_ANYCAST_ADDRESSES_RFC4291, RESERVED_SUBNET_ANYCAST_PREFIXLEN) == 0)
                return false;

        return true;
}

static int make_stable_private_address(Link *link, const struct in6_addr *prefix, uint8_t prefix_len, uint8_t dad_counter, struct in6_addr **ret) {
        _cleanup_free_ struct in6_addr *addr = NULL;
        sd_id128_t secret_key;
        struct siphash state;
        uint64_t rid;
        size_t l;
        int r;

        /* According to rfc7217 section 5.1
         * RID = F(Prefix, Net_Iface, Network_ID, DAD_Counter, secret_key) */

        r = sd_id128_get_machine_app_specific(NDISC_APP_ID, &secret_key);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to generate key for IPv6 stable private address: %m");

        siphash24_init(&state, secret_key.bytes);

        l = MAX(DIV_ROUND_UP(prefix_len, 8), 8);
        siphash24_compress(prefix, l, &state);
        siphash24_compress_string(link->ifname, &state);
        /* Only last 8 bytes of IB MAC are stable */
        if (link->iftype == ARPHRD_INFINIBAND)
                siphash24_compress(&link->hw_addr.infiniband[12], 8, &state);
        else
                siphash24_compress(link->hw_addr.bytes, link->hw_addr.length, &state);
        siphash24_compress(&dad_counter, sizeof(uint8_t), &state);

        rid = htole64(siphash24_finalize(&state));

        addr = new(struct in6_addr, 1);
        if (!addr)
                return log_oom();

        memcpy(addr->s6_addr, prefix->s6_addr, l);
        memcpy(addr->s6_addr + l, &rid, 16 - l);

        if (!stable_private_address_is_valid(addr)) {
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(addr);
        return 1;
}

int ndisc_router_generate_addresses(Link *link, struct in6_addr *address, uint8_t prefixlen, Set **ret) {
        _cleanup_set_free_free_ Set *addresses = NULL;
        IPv6Token *j;
        int r;

        assert(link);
        assert(address);
        assert(ret);

        addresses = set_new(&in6_addr_hash_ops);
        if (!addresses)
                return log_oom();

        ORDERED_SET_FOREACH(j, link->network->ipv6_tokens) {
                _cleanup_free_ struct in6_addr *new_address = NULL;

                if (j->address_generation_type == IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE
                    && (in6_addr_is_null(&j->prefix) || in6_addr_equal(&j->prefix, address))) {
                        /* While this loop uses dad_counter and a retry limit as specified in RFC 7217, the loop
                         * does not actually attempt Duplicate Address Detection; the counter will be incremented
                         * only when the address generation algorithm produces an invalid address, and the loop
                         * may exit with an address which ends up being unusable due to duplication on the link. */
                        for (; j->dad_counter < DAD_CONFLICTS_IDGEN_RETRIES_RFC7217; j->dad_counter++) {
                                r = make_stable_private_address(link, address, prefixlen, j->dad_counter, &new_address);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        break;
                        }
                } else if (j->address_generation_type == IPV6_TOKEN_ADDRESS_GENERATION_STATIC) {
                        new_address = new(struct in6_addr, 1);
                        if (!new_address)
                                return log_oom();

                        memcpy(new_address->s6_addr, address->s6_addr, 8);
                        memcpy(new_address->s6_addr + 8, j->prefix.s6_addr + 8, 8);
                }

                if (new_address) {
                        r = set_put(addresses, new_address);
                        if (r < 0)
                                return log_link_error_errno(link, r, "Failed to store SLAAC address: %m");
                        else if (r == 0)
                                log_link_debug_errno(link, r, "Generated SLAAC address is duplicated, ignoring.");
                        else
                                TAKE_PTR(new_address);
                }
        }

        /* fall back to EUI-64 if no tokens provided addresses */
        if (set_isempty(addresses)) {
                _cleanup_free_ struct in6_addr *new_address = NULL;

                new_address = newdup(struct in6_addr, address, 1);
                if (!new_address)
                        return log_oom();

                r = generate_ipv6_eui_64_address(link, new_address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to generate EUI64 address: %m");

                r = set_put(addresses, new_address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to store SLAAC address: %m");

                TAKE_PTR(new_address);
        }

        *ret = TAKE_PTR(addresses);

        return 0;
}

static int ipv6token_new(IPv6Token **ret) {
        IPv6Token *p;

        p = new(IPv6Token, 1);
        if (!p)
                return -ENOMEM;

        *p = (IPv6Token) {
                 .address_generation_type = IPV6_TOKEN_ADDRESS_GENERATION_NONE,
        };

        *ret = TAKE_PTR(p);

        return 0;
}

static void ipv6_token_hash_func(const IPv6Token *p, struct siphash *state) {
        siphash24_compress(&p->address_generation_type, sizeof(p->address_generation_type), state);
        siphash24_compress(&p->prefix, sizeof(p->prefix), state);
}

static int ipv6_token_compare_func(const IPv6Token *a, const IPv6Token *b) {
        int r;

        r = CMP(a->address_generation_type, b->address_generation_type);
        if (r != 0)
                return r;

        return memcmp(&a->prefix, &b->prefix, sizeof(struct in6_addr));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ipv6_token_hash_ops,
                IPv6Token,
                ipv6_token_hash_func,
                ipv6_token_compare_func,
                free);

int config_parse_address_generation_type(
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

        _cleanup_free_ IPv6Token *token = NULL;
        union in_addr_union buffer;
        Network *network = data;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                network->ipv6_tokens = ordered_set_free(network->ipv6_tokens);
                return 0;
        }

        r = ipv6token_new(&token);
        if (r < 0)
                return log_oom();

        if ((p = startswith(rvalue, "prefixstable"))) {
                token->address_generation_type = IPV6_TOKEN_ADDRESS_GENERATION_PREFIXSTABLE;
                if (*p == ':')
                        p++;
                else if (*p == '\0')
                        p = NULL;
                else {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Invalid IPv6 token mode in %s=, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
        } else {
                token->address_generation_type = IPV6_TOKEN_ADDRESS_GENERATION_STATIC;
                p = startswith(rvalue, "static:");
                if (!p)
                        p = rvalue;
        }

        if (p) {
                r = in_addr_from_string(AF_INET6, p, &buffer);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse IP address in %s=, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (token->address_generation_type == IPV6_TOKEN_ADDRESS_GENERATION_STATIC &&
                    in_addr_is_null(AF_INET6, &buffer)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "IPv6 address in %s= cannot be the ANY address, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                token->prefix = buffer.in6;
        }

        r = ordered_set_ensure_put(&network->ipv6_tokens, &ipv6_token_hash_ops, token);
        if (r == -ENOMEM)
                return log_oom();
        if (r == -EEXIST)
                log_syntax(unit, LOG_DEBUG, filename, line, r,
                           "IPv6 token '%s' is duplicated, ignoring: %m", rvalue);
        else if (r < 0)
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to store IPv6 token '%s', ignoring: %m", rvalue);
        else
                TAKE_PTR(token);

        return 0;
}
