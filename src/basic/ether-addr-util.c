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

bool ether_addr_is_null(const struct ether_addr *addr) {
        assert(addr);

        return  addr->ether_addr_octet[0] == 0 &&
                addr->ether_addr_octet[1] == 0 &&
                addr->ether_addr_octet[2] == 0 &&
                addr->ether_addr_octet[3] == 0 &&
                addr->ether_addr_octet[4] == 0 &&
                addr->ether_addr_octet[5] == 0;
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
