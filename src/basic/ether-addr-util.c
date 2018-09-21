/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <sys/types.h>

#include "ether-addr-util.h"
#include "macro.h"
#include "string-util.h"

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

int ether_addr_compare(const void *a, const void *b) {
        assert(a);
        assert(b);

        return memcmp(a, b, ETH_ALEN);
}

static void ether_addr_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(struct ether_addr), state);
}

const struct hash_ops ether_addr_hash_ops = {
        .hash = ether_addr_hash_func,
        .compare = ether_addr_compare
};

int ether_addr_from_string(const char *s, struct ether_addr *ret) {
        size_t pos = 0, n, field;
        char sep = '\0';
        const char *hex = HEXDIGITS, *hexoff;
        size_t x;
        bool touched;

#define parse_fields(v)                                         \
        for (field = 0; field < ELEMENTSOF(v); field++) {       \
                touched = false;                                \
                for (n = 0; n < (2 * sizeof(v[0])); n++) {      \
                        if (s[pos] == '\0')                     \
                                break;                          \
                        hexoff = strchr(hex, s[pos]);           \
                        if (!hexoff)                            \
                                break;                          \
                        assert(hexoff >= hex);                  \
                        x = hexoff - hex;                       \
                        if (x >= 16)                            \
                                x -= 6; /* A-F */               \
                        assert(x < 16);                         \
                        touched = true;                         \
                        v[field] <<= 4;                         \
                        v[field] += x;                          \
                        pos++;                                  \
                }                                               \
                if (!touched)                                   \
                        return -EINVAL;                         \
                if (field < (ELEMENTSOF(v)-1)) {                \
                        if (s[pos] != sep)                      \
                                return -EINVAL;                 \
                        else                                    \
                                pos++;                          \
                }                                               \
        }

        assert(s);
        assert(ret);

        s += strspn(s, WHITESPACE);
        sep = s[strspn(s, hex)];

        if (sep == '.') {
                uint16_t shorts[3] = { 0 };

                parse_fields(shorts);

                if (s[pos] != '\0')
                        return -EINVAL;

                for (n = 0; n < ELEMENTSOF(shorts); n++) {
                        ret->ether_addr_octet[2*n] = ((shorts[n] & (uint16_t)0xff00) >> 8);
                        ret->ether_addr_octet[2*n + 1] = (shorts[n] & (uint16_t)0x00ff);
                }

        } else if (IN_SET(sep, ':', '-')) {
                struct ether_addr out = ETHER_ADDR_NULL;

                parse_fields(out.ether_addr_octet);

                if (s[pos] != '\0')
                        return -EINVAL;

                for (n = 0; n < ELEMENTSOF(out.ether_addr_octet); n++)
                        ret->ether_addr_octet[n] = out.ether_addr_octet[n];

        } else
                return -EINVAL;

        return 0;
}
