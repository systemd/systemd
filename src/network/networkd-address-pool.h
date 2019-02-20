/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct AddressPool AddressPool;

#include "in-addr-util.h"
#include "list.h"

typedef struct Manager Manager;

struct AddressPool {
        Manager *manager;

        int family;
        unsigned prefixlen;

        union in_addr_union in_addr;

        LIST_FIELDS(AddressPool, address_pools);
};

int address_pool_new_from_string(Manager *m, AddressPool **ret, int family, const char *p, unsigned prefixlen);
void address_pool_free(AddressPool *p);

int address_pool_acquire(AddressPool *p, unsigned prefixlen, union in_addr_union *found);
