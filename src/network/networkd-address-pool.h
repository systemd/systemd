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

void address_pool_free(AddressPool *p);

int address_pool_setup_default(Manager *m);
int address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found);
