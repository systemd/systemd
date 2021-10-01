/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "sd-id128.h"

#include "memory-util.h"
#include "networkd-address-generation.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "string-util.h"

#define DAD_CONFLICTS_IDGEN_RETRIES_RFC7217 3

/* https://www.iana.org/assignments/ipv6-interface-ids/ipv6-interface-ids.xml */
#define SUBNET_ROUTER_ANYCAST_ADDRESS            ((const struct in6_addr) { .s6_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } })
#define SUBNET_ROUTER_ANYCAST_PREFIXLEN          64
#define RESERVED_INTERFACE_IDENTIFIERS_ADDRESS   ((const struct in6_addr) { .s6_addr = { 0x02, 0x00, 0x5E, 0xFF, 0xFE } })
#define RESERVED_INTERFACE_IDENTIFIERS_PREFIXLEN 40
#define RESERVED_SUBNET_ANYCAST_ADDRESSES        ((const struct in6_addr) { .s6_addr = { 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80 } })
#define RESERVED_SUBNET_ANYCAST_PREFIXLEN        57

#define NDISC_APP_ID   SD_ID128_MAKE(13,ac,81,a7,d5,3f,49,78,92,79,5d,0c,29,3a,bc,7e)

typedef enum AddressGenerationType {
        ADDRESS_GENERATION_STATIC,
        ADDRESS_GENERATION_PREFIXSTABLE,
        _ADDRESS_GENERATION_TYPE_MAX,
        _ADDRESS_GENERATION_TYPE_INVALID = -EINVAL,
} AddressGenerationType;

typedef struct IPv6Token {
        AddressGenerationType type;
        struct in6_addr address;
} IPv6Token;

void generate_eui64_address(const Link *link, const struct in6_addr *prefix, struct in6_addr *ret) {
        assert(link);
        assert(prefix);
        assert(ret);

        memcpy(ret->s6_addr, prefix, 8);

        if (link->iftype == ARPHRD_INFINIBAND)
                /* Use last 8 byte. See RFC4391 section 8 */
                memcpy(&ret->s6_addr[8], &link->hw_addr.infiniband[INFINIBAND_ALEN - 8], 8);
        else {
                /* see RFC4291 section 2.5.1 */
                ret->s6_addr[8]  = link->hw_addr.ether.ether_addr_octet[0];
                ret->s6_addr[9]  = link->hw_addr.ether.ether_addr_octet[1];
                ret->s6_addr[10] = link->hw_addr.ether.ether_addr_octet[2];
                ret->s6_addr[11] = 0xff;
                ret->s6_addr[12] = 0xfe;
                ret->s6_addr[13] = link->hw_addr.ether.ether_addr_octet[3];
                ret->s6_addr[14] = link->hw_addr.ether.ether_addr_octet[4];
                ret->s6_addr[15] = link->hw_addr.ether.ether_addr_octet[5];
        }

        ret->s6_addr[8] ^= 1 << 1;
}

static bool stable_private_address_is_valid(const struct in6_addr *addr) {
        assert(addr);

        /* According to rfc4291, generated address should not be in the following ranges. */

        if (in6_addr_prefix_covers(&SUBNET_ROUTER_ANYCAST_ADDRESS, SUBNET_ROUTER_ANYCAST_PREFIXLEN, addr))
                return false;

        if (in6_addr_prefix_covers(&RESERVED_INTERFACE_IDENTIFIERS_ADDRESS, RESERVED_INTERFACE_IDENTIFIERS_PREFIXLEN, addr))
                return false;

        if (in6_addr_prefix_covers(&RESERVED_SUBNET_ANYCAST_ADDRESSES, RESERVED_SUBNET_ANYCAST_PREFIXLEN, addr))
                return false;

        return true;
}

static void generate_stable_private_address_one(
                Link *link,
                const sd_id128_t *secret_key,
                const struct in6_addr *prefix,
                uint8_t dad_counter,
                struct in6_addr *ret) {

        struct siphash state;
        uint64_t rid;

        assert(link);
        assert(secret_key);
        assert(prefix);
        assert(ret);

        /* According to RFC7217 section 5.1
         * RID = F(Prefix, Net_Iface, Network_ID, DAD_Counter, secret_key) */

        siphash24_init(&state, secret_key->bytes);

        siphash24_compress(prefix, 8, &state);
        siphash24_compress_string(link->ifname, &state);
        if (link->iftype == ARPHRD_INFINIBAND)
                /* Only last 8 bytes of IB MAC are stable */
                siphash24_compress(&link->hw_addr.infiniband[INFINIBAND_ALEN - 8], 8, &state);
        else
                siphash24_compress(link->hw_addr.bytes, link->hw_addr.length, &state);
        siphash24_compress(&dad_counter, sizeof(uint8_t), &state);

        rid = htole64(siphash24_finalize(&state));

        memcpy(ret->s6_addr, prefix->s6_addr, 8);
        memcpy(ret->s6_addr + 8, &rid, 8);
}

static int generate_stable_private_address(
                Link *link,
                const sd_id128_t *app_id,
                const struct in6_addr *prefix,
                struct in6_addr *ret) {

        struct in6_addr addr;
        sd_id128_t secret_key;
        uint8_t i;
        int r;

        assert(link);
        assert(app_id);
        assert(prefix);
        assert(ret);

        r = sd_id128_get_machine_app_specific(*app_id, &secret_key);
        if (r < 0)
               return log_link_debug_errno(link, r, "Failed to generate secret key for IPv6 stable private address: %m");

        /* While this loop uses dad_counter and a retry limit as specified in RFC 7217, the loop does
         * not actually attempt Duplicate Address Detection; the counter will be incremented only when
         * the address generation algorithm produces an invalid address, and the loop may exit with an
         * address which ends up being unusable due to duplication on the link. */
        for (i = 0; i < DAD_CONFLICTS_IDGEN_RETRIES_RFC7217; i++) {
                generate_stable_private_address_one(link, &secret_key, prefix, i, &addr);

                if (stable_private_address_is_valid(&addr))
                        break;
        }
        if (i >= DAD_CONFLICTS_IDGEN_RETRIES_RFC7217)
                /* propagate recognizable errors. */
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(ENOANO),
                                            "Failed to generate stable private address.");

        *ret = addr;
        return 0;
}

static int generate_addresses(
                Link *link,
                Set *tokens,
                const sd_id128_t *app_id,
                const struct in6_addr *prefix,
                uint8_t prefixlen,
                Set **ret) {

        _cleanup_set_free_ Set *addresses = NULL;
        struct in6_addr masked;
        IPv6Token *j;
        int r;

        assert(link);
        assert(app_id);
        assert(prefix);
        assert(prefixlen > 0 && prefixlen <= 64);
        assert(ret);

        masked = *prefix;
        in6_addr_mask(&masked, prefixlen);

        SET_FOREACH(j, tokens) {
                struct in6_addr addr, *copy;

                switch (j->type) {
                case ADDRESS_GENERATION_STATIC:
                        memcpy(addr.s6_addr, masked.s6_addr, 8);
                        memcpy(addr.s6_addr + 8, j->address.s6_addr + 8, 8);
                        break;

                case ADDRESS_GENERATION_PREFIXSTABLE:
                        if (in6_addr_is_set(&j->address) && !in6_addr_equal(&j->address, &masked))
                                continue;

                        if (generate_stable_private_address(link, app_id, &masked, &addr) < 0)
                                continue;

                        break;

                default:
                        assert_not_reached();
                }

                copy = newdup(struct in6_addr, &addr, 1);
                if (!copy)
                        return -ENOMEM;

                r = set_ensure_consume(&addresses, &in6_addr_hash_ops_free, copy);
                if (r < 0)
                        return r;
        }

        /* fall back to EUI-64 if no token is provided */
        if (set_isempty(addresses)) {
                struct in6_addr *addr;

                addr = new(struct in6_addr, 1);
                if (!addr)
                        return -ENOMEM;

                generate_eui64_address(link, &masked, addr);

                r = set_ensure_consume(&addresses, &in6_addr_hash_ops_free, addr);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(addresses);
        return 0;
}

int ndisc_generate_addresses(Link *link, const struct in6_addr *prefix, uint8_t prefixlen, Set **ret) {
        return generate_addresses(link, link->network->ndisc_tokens, &NDISC_APP_ID, prefix, prefixlen, ret);
}

static void ipv6_token_hash_func(const IPv6Token *p, struct siphash *state) {
        siphash24_compress(&p->type, sizeof(p->type), state);
        siphash24_compress(&p->address, sizeof(p->address), state);
}

static int ipv6_token_compare_func(const IPv6Token *a, const IPv6Token *b) {
        int r;

        r = CMP(a->type, b->type);
        if (r != 0)
                return r;

        return memcmp(&a->address, &b->address, sizeof(struct in6_addr));
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ipv6_token_hash_ops,
                IPv6Token,
                ipv6_token_hash_func,
                ipv6_token_compare_func,
                free);

static int ipv6_token_add(Set **tokens, AddressGenerationType type, const struct in6_addr *addr) {
        IPv6Token *p;

        assert(tokens);
        assert(type >= 0 && type < _ADDRESS_GENERATION_TYPE_MAX);
        assert(addr);

        p = new(IPv6Token, 1);
        if (!p)
                return -ENOMEM;

        *p = (IPv6Token) {
                 .type = type,
                 .address = *addr,
        };

        return set_ensure_consume(tokens, &ipv6_token_hash_ops, p);
}

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

        union in_addr_union buffer = {};
        AddressGenerationType type;
        Set **tokens = data;
        const char *p;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *tokens = set_free(*tokens);
                return 0;
        }

        if ((p = startswith(rvalue, "prefixstable"))) {
                type = ADDRESS_GENERATION_PREFIXSTABLE;

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
                type = ADDRESS_GENERATION_STATIC;

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
        }

        switch (type) {
        case ADDRESS_GENERATION_STATIC:
                /* Only last 64 bits are used. */
                memzero(buffer.in6.s6_addr, 8);

                if (in6_addr_is_null(&buffer.in6)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "IPv6 address in %s= cannot be the ANY address, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                break;

        case ADDRESS_GENERATION_PREFIXSTABLE:
                /* At most, the initial 64 bits are used. */
                (void) in6_addr_mask(&buffer.in6, 64);
                break;

        default:
                assert_not_reached();
        }

        r = ipv6_token_add(tokens, type, &buffer.in6);
        if (r < 0)
                return log_oom();

        return 0;
}
