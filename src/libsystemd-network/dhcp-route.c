/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-lease.h"

#include "dhcp-route.h"  /* IWYU pragma: keep */

int sd_dhcp_route_get_destination(sd_dhcp_route *route, struct in_addr *ret) {
        assert_return(route, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = route->dst_addr;
        return 0;
}

int sd_dhcp_route_get_destination_prefix_length(sd_dhcp_route *route, uint8_t *ret) {
        assert_return(route, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = route->dst_prefixlen;
        return 0;
}

int sd_dhcp_route_get_gateway(sd_dhcp_route *route, struct in_addr *ret) {
        assert_return(route, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = route->gw_addr;
        return 0;
}
