/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "af-list.h"
#include "alloc-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"

static void print_local_addresses(struct local_address *a, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++) {
                _cleanup_free_ char *b = NULL;

                assert_se(in_addr_to_string(a[i].family, &a[i].address, &b) >= 0);
                printf("%s if%i scope=%i metric=%u address=%s\n", af_to_name(a[i].family), a[i].ifindex, a[i].scope, a[i].metric, b);
        }
}

int main(int argc, char *argv[]) {
        struct local_address *a;
        int n;

        a = NULL;
        n = local_addresses(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);

        printf("Local Addresses:\n");
        print_local_addresses(a, (unsigned) n);
        a = mfree(a);

        n = local_gateways(NULL, 0, AF_UNSPEC, &a);
        assert_se(n >= 0);

        printf("Local Gateways:\n");
        print_local_addresses(a, (unsigned) n);
        free(a);

        return 0;
}
