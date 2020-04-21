/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "alloc-util.h"
#include "dhcp-internal.h"
#include "dhcp-server-internal.h"
#include "memory-util.h"
#include "strv.h"
#include "utf8.h"


static sd_dhcp_static_lease* sd_dhcp_static_lease_free(sd_dhcp_static_lease *i) {
        if (!i)
                return NULL;

        free(i->data);
        return mfree(i);
}


// void static_lease_client_id_hash_func(const DHCPClientId *id, struct siphash *state) {
//         assert(id);
//         assert(id->length);
//         assert(id->data);

//         uint8_t bla[7];
//         uint8_t *t = id->data;
//         // bla[0]=1;
//         // bla[1]=t[0];
//         // bla[2]=t[1];
//         // bla[3]=t[2];
//         // bla[4]=t[3];
//         // bla[5]=t[4];
//         // bla[6]=t[5];
//         // bla[7]=t[6];

//         printf("I am hashing the mac length %ld\n",id->length);
//         for (int i = 0; i < id->length; i++)
//         {
//                 printf("%x ", t[i]);
//         }
//         printf("\n");

//         siphash24_compress(&id->length, sizeof(id->length), state);
//         siphash24_compress(id->data, id->length, state);
// }

int sd_dhcp_static_lease_new(DHCPClientId *client_id, be32_t address, sd_dhcp_static_lease **ret) {
        assert_return(ret, -EINVAL);
        assert_return(address, -EINVAL);

        sd_dhcp_static_lease *p = new(sd_dhcp_static_lease, 1);
        if (!p)
                return -ENOMEM;

        printf("addres converted %u\n", address);
        *p = (sd_dhcp_static_lease) {
                .n_ref = 1,
                .client_id = *client_id,
                .address = address
        };

        *ret = TAKE_PTR(p);
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_static_lease, sd_dhcp_static_lease, sd_dhcp_static_lease_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dhcp_static_leases_hash_ops,
                DHCPClientId,
                client_id_hash_func,
                client_id_compare_func,
                sd_dhcp_static_lease,
                sd_dhcp_static_lease_unref);