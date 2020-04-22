/* SPDX-License-Identifier: LGPL-2.1+ */

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
        return mfree(i);
}

int sd_dhcp_static_lease_new(DHCPClientId *client_id, be32_t address, sd_dhcp_static_lease **ret) {
        assert_return(ret, -EINVAL);
        assert_return(address, -EINVAL);

        sd_dhcp_static_lease *p = new(sd_dhcp_static_lease, 1);
        if (!p)
                return -ENOMEM;

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