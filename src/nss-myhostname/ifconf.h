/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef fooifconfhfoo
#define fooifconfhfoo

#include <sys/socket.h>

/***
  This file is part of nss-myhostname.

  Copyright 2008-2011 Lennart Poettering

  nss-myhostname is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License
  as published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  nss-myhostname is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with nss-myhostname; If not, see
  <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <sys/types.h>
#include <assert.h>

struct address {
        unsigned char family;
        uint8_t address[16];
        unsigned char scope;
        int ifindex;
};

#define _public_ __attribute__ ((visibility("default")))
#define _hidden_ __attribute__ ((visibility("hidden")))

int ifconf_acquire_addresses(struct address **_list, unsigned *_n_list) _hidden_;

static inline size_t PROTO_ADDRESS_SIZE(int proto) {
        assert(proto == AF_INET || proto == AF_INET6);

        return proto == AF_INET6 ? 16 : 4;
}

static inline int address_compare(const void *_a, const void *_b) {
        const struct address *a = _a, *b = _b;

        /* Order lowest scope first, IPv4 before IPv6, lowest interface index first */

        if (a->scope < b->scope)
                return -1;
        if (a->scope > b->scope)
                return 1;

        if (a->family == AF_INET && b->family == AF_INET6)
                return -1;
        if (a->family == AF_INET6 && b->family == AF_INET)
                return 1;

        if (a->ifindex < b->ifindex)
                return -1;
        if (a->ifindex > b->ifindex)
                return 1;

        return 0;
}


#endif
