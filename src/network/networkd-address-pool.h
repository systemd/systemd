/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "in-addr-util.h"

typedef struct Manager Manager;

typedef struct AddressPool {
        Manager *manager;

        int family;
        unsigned prefixlen;
        union in_addr_union in_addr;
} AddressPool;

int address_pool_setup_default(Manager *m);
int address_pool_acquire(Manager *m, int family, unsigned prefixlen, union in_addr_union *found);
