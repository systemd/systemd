/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <sys/types.h>

#include "ether-addr-util.h"
#include "hexdecoct.h"
#include "macro.h"
#include "string-util.h"

char *hw_addr_to_string_full(
                const struct hw_addr_data *addr,
                HardwareAddressToStringFlags flags,
                char buffer[static HW_ADDR_TO_STRING_MAX]) {

        assert(addr);
        assert(buffer);
        assert(addr->length <= HW_ADDR_MAX_SIZE);

        for (size_t i = 0, j = 0; i < addr->length; i++) {
                buffer[j++] = hexchar(addr->bytes[i] >> 4);
                buffer[j++] = hexchar(addr->bytes[i] & 0x0f);
                if (!FLAGS_SET(flags, HW_ADDR_TO_STRING_NO_COLON))
                        buffer[j++] = ':';
        }

        buffer[addr->length == 0 || FLAGS_SET(flags, HW_ADDR_TO_STRING_NO_COLON) ?
               addr->length * 2 :
               addr->length * 3 - 1] = '\0';
        return buffer;
}

struct hw_addr_data *hw_addr_set(struct hw_addr_data *addr, const uint8_t *bytes, size_t length) {
        assert(addr);
        assert(length <= HW_ADDR_MAX_SIZE);

        addr->length = length;
        memcpy_safe(addr->bytes, bytes, length);
        return addr;
}

int hw_addr_compare(const struct hw_addr_data *a, const struct hw_addr_data *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->length, b->length);
        if (r != 0)
                return r;

        return memcmp(a->bytes, b->bytes, a->length);
}

void hw_addr_hash_func(const struct hw_addr_data *p, struct siphash *state) {
        assert(p);
        assert(state);

        siphash24_compress_typesafe(p->length, state);
        siphash24_compress_safe(p->bytes, p->length, state);
}

DEFINE_HASH_OPS(hw_addr_hash_ops, struct hw_addr_data, hw_addr_hash_func, hw_addr_compare);
DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(hw_addr_hash_ops_free, struct hw_addr_data, hw_addr_hash_func, hw_addr_compare, free);

char* ether_addr_to_string(const struct ether_addr *addr, char buffer[ETHER_ADDR_TO_STRING_MAX]) {
        assert(addr);
        assert(buffer);

        /* Like ether_ntoa() but uses %02x instead of %x to print
         * ethernet addresses, which makes them look less funny. Also,
         * doesn't use a static buffer. */

        sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
                addr->ether_addr_octet[0],
                addr->ether_addr_octet[1],
                addr->ether_addr_octet[2],
                addr->ether_addr_octet[3],
                addr->ether_addr_octet[4],
                addr->ether_addr_octet[5]);

        return buffer;
}

int ether_addr_to_string_alloc(const struct ether_addr *addr, char **ret) {
        char *buf;

        assert(addr);
        assert(ret);

        buf = new(char, ETHER_ADDR_TO_STRING_MAX);
        if (!buf)
                return -ENOMEM;

        ether_addr_to_string(addr, buf);

        *ret = buf;
        return 0;
}

int ether_addr_compare(const struct ether_addr *a, const struct ether_addr *b) {
        return memcmp(a, b, ETH_ALEN);
}

static void ether_addr_hash_func(const struct ether_addr *p, struct siphash *state) {
        siphash24_compress_typesafe(*p, state);
}

DEFINE_HASH_OPS(ether_addr_hash_ops, struct ether_addr, ether_addr_hash_func, ether_addr_compare);
DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(ether_addr_hash_ops_free, struct ether_addr, ether_addr_hash_func, ether_addr_compare, free);

static int parse_hw_addr_one_field(const char **s, char sep, size_t len, uint8_t *buf) {
        const char *hex = HEXDIGITS, *p;
        uint16_t data = 0;
        bool cont;

        assert(s);
        assert(*s);
        assert(IN_SET(len, 1, 2));
        assert(buf);

        p = *s;

        for (size_t i = 0; i < len * 2; i++) {
                const char *hexoff;
                size_t x;

                if (*p == '\0' || *p == sep) {
                        if (i == 0)
                                return -EINVAL;
                        break;
                }

                hexoff = strchr(hex, *p);
                if (!hexoff)
                        return -EINVAL;

                assert(hexoff >= hex);
                x = hexoff - hex;
                if (x >= 16)
                        x -= 6; /* A-F */

                assert(x < 16);
                data <<= 4;
                data += x;

                p++;
        }

        if (*p != '\0' && *p != sep)
                return -EINVAL;

        switch (len) {
        case 1:
                buf[0] = data;
                break;
        case 2:
                buf[0] = (data & 0xff00) >> 8;
                buf[1] = data & 0xff;
                break;
        default:
                assert_not_reached();
        }

        cont = *p == sep;
        *s = p + cont;
        return cont;
}

int parse_hw_addr_full(const char *s, size_t expected_len, struct hw_addr_data *ret) {
        size_t field_size, max_len, len = 0;
        uint8_t bytes[HW_ADDR_MAX_SIZE];
        char sep;
        int r;

        assert(s);
        assert(expected_len <= HW_ADDR_MAX_SIZE || expected_len == SIZE_MAX);
        assert(ret);

        /* This accepts the following formats:
         *
         * Dot separated 2 bytes format: xxyy.zzaa.bbcc
         * Colon separated 1 bytes format: xx:yy:zz:aa:bb:cc
         * Hyphen separated 1 bytes format: xx-yy-zz-aa-bb-cc
         *
         * Moreover, if expected_len == 0, 4, or 16, this also accepts:
         *
         * IPv4 format: used by IPv4 tunnel, e.g. ipgre
         * IPv6 format: used by IPv6 tunnel, e.g. ip6gre
         *
         * The expected_len argument controls the length of acceptable addresses:
         *
         * 0: accepts 4 (AF_INET), 16 (AF_INET6), 6 (ETH_ALEN), or 20 (INFINIBAND_ALEN).
         * SIZE_MAX: accepts arbitrary length, but at least one separator must be included.
         * Otherwise: accepts addresses with matching length.
         */

        if (IN_SET(expected_len, 0, sizeof(struct in_addr), sizeof(struct in6_addr))) {
                union in_addr_union a;
                int family;

                if (expected_len == 0)
                        r = in_addr_from_string_auto(s, &family, &a);
                else {
                        family = expected_len == sizeof(struct in_addr) ? AF_INET : AF_INET6;
                        r = in_addr_from_string(family, s, &a);
                }
                if (r >= 0) {
                        ret->length = FAMILY_ADDRESS_SIZE(family);
                        memcpy(ret->bytes, a.bytes, ret->length);
                        return 0;
                }
        }

        max_len =
                expected_len == 0 ? INFINIBAND_ALEN :
                expected_len == SIZE_MAX ? HW_ADDR_MAX_SIZE : expected_len;
        sep = s[strspn(s, HEXDIGITS)];

        if (sep == '.')
                field_size = 2;
        else if (IN_SET(sep, ':', '-'))
                field_size = 1;
        else
                return -EINVAL;

        if (max_len % field_size != 0)
                return -EINVAL;

        for (size_t i = 0; i < max_len / field_size; i++) {
                r = parse_hw_addr_one_field(&s, sep, field_size, bytes + i * field_size);
                if (r < 0)
                        return r;
                if (r == 0) {
                        len = (i + 1) * field_size;
                        break;
                }
        }

        if (len == 0)
                return -EINVAL;

        if (expected_len == 0) {
                if (!IN_SET(len, 4, 16, ETH_ALEN, INFINIBAND_ALEN))
                        return -EINVAL;
        } else if (expected_len != SIZE_MAX) {
                if (len != expected_len)
                        return -EINVAL;
        }

        ret->length = len;
        memcpy(ret->bytes, bytes, ret->length);
        return 0;
}

int parse_ether_addr(const char *s, struct ether_addr *ret) {
        struct hw_addr_data a;
        int r;

        assert(s);
        assert(ret);

        r = parse_hw_addr_full(s, ETH_ALEN, &a);
        if (r < 0)
                return r;

        *ret = a.ether;
        return 0;
}

void ether_addr_mark_random(struct ether_addr *addr) {
        assert(addr);

        /* see eth_random_addr in the kernel */
        addr->ether_addr_octet[0] &= 0xfe;        /* clear multicast bit */
        addr->ether_addr_octet[0] |= 0x02;        /* set local assignment bit (IEEE802) */
}
