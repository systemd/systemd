/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen

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

bool ether_addr_equal(const struct ether_addr *a, const struct ether_addr *b) {
        assert(a);
        assert(b);

        return  a->ether_addr_octet[0] == b->ether_addr_octet[0] &&
                a->ether_addr_octet[1] == b->ether_addr_octet[1] &&
                a->ether_addr_octet[2] == b->ether_addr_octet[2] &&
                a->ether_addr_octet[3] == b->ether_addr_octet[3] &&
                a->ether_addr_octet[4] == b->ether_addr_octet[4] &&
                a->ether_addr_octet[5] == b->ether_addr_octet[5];
}

int ether_addr_from_string(const char *s, struct ether_addr *ret, size_t *offset) {
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
                        if (hexoff == NULL)                     \
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

        sep = s[strspn(s, hex)];
        if (sep == '\n')
                return -EINVAL;
        if (strchr(":.-", sep) == NULL)
                return -EINVAL;

        if (sep == '.') {
                uint16_t shorts[3] = { 0 };

                parse_fields(shorts);

                for (n = 0; n < ELEMENTSOF(shorts); n++) {
                        ret->ether_addr_octet[2*n] = ((shorts[n] & (uint16_t)0xff00) >> 8);
                        ret->ether_addr_octet[2*n + 1] = (shorts[n] & (uint16_t)0x00ff);
                }
        } else {
                struct ether_addr out = { .ether_addr_octet = { 0 } };

                parse_fields(out.ether_addr_octet);

                for (n = 0; n < ELEMENTSOF(out.ether_addr_octet); n++)
                        ret->ether_addr_octet[n] = out.ether_addr_octet[n];
        }

        if (offset)
                *offset = pos;
        return 0;
}
