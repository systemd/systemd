/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "alloc-util.h"
#include "dhcp-server-internal.h"
#include "memory-util.h"
#include "strv.h"

static sd_dhcp_static_lease *sd_dhcp_static_lease_free(sd_dhcp_static_lease *i) {
        if (!i)
                return NULL;

        free(i->client_id.data);
        return mfree(i);
}

int sd_dhcp_static_lease_set_client_id_by_mac(
                sd_dhcp_static_lease *lease,
                const uint8_t *mac_addr,
                size_t mac_addr_size) {
        uint8_t *data;

        assert_return(lease, -EINVAL);
        assert_return(mac_addr, -EINVAL);
        assert_return(mac_addr_size == ETH_ALEN, -EINVAL);

        data = new(uint8_t, mac_addr_size + 1);
        if (!data)
                return -ENOMEM;

        /* set client id type to 1: Ethernet Link-Layer (RFC 2132) */
        data[0] = 0x01;
        memcpy(data + 1, mac_addr, mac_addr_size);

        free_and_replace(lease->client_id.data, data);

        lease->client_id.length = mac_addr_size + 1;

        return 0;
}

int sd_dhcp_static_lease_unset_client_id(sd_dhcp_static_lease *lease) {
        assert_return(lease, -EINVAL);

        lease->client_id.data = mfree(lease->client_id.data);
        lease->client_id.length = 0;

        return 0;
}

int sd_dhcp_static_lease_is_address_set(sd_dhcp_static_lease *lease){
        assert_return(lease, -EINVAL);

        return lease->address == 0;
}

int sd_dhcp_static_lease_set_address(sd_dhcp_static_lease *lease, const struct in_addr *address) {
        assert_return(lease, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(address->s_addr != 0, -EINVAL);

        lease->address = address->s_addr;

        return 0;
}

int sd_dhcp_static_lease_unset_address(sd_dhcp_static_lease *lease) {
        assert_return(lease, -EINVAL);

        lease->address = 0;

        return 0;
}

int sd_dhcp_static_lease_new(sd_dhcp_static_lease **ret) {
        sd_dhcp_static_lease *p;

        assert_return(ret, -EINVAL);

        p = new(sd_dhcp_static_lease, 1);
        if (!p)
                return -ENOMEM;

        *p = (sd_dhcp_static_lease) {
                .n_ref = 1,
        };

        *ret = TAKE_PTR(p);
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_static_lease, sd_dhcp_static_lease, sd_dhcp_static_lease_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        dhcp_static_lease_hash_ops,
        DHCPClientId,
        client_id_hash_func,
        client_id_compare_func,
        sd_dhcp_static_lease,
        sd_dhcp_static_lease_unref);
