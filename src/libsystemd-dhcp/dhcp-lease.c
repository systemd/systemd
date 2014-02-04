/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <sys/param.h>

#include "util.h"
#include "list.h"

#include "dhcp-protocol.h"
#include "dhcp-internal.h"
#include "dhcp-lease.h"
#include "sd-dhcp-client.h"

int sd_dhcp_lease_get_address(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        addr->s_addr = lease->address;

        return 0;
}

int sd_dhcp_lease_get_mtu(sd_dhcp_lease *lease, uint16_t *mtu) {
        assert_return(lease, -EINVAL);
        assert_return(mtu, -EINVAL);

        if (lease->mtu)
                *mtu = lease->mtu;
        else
                return -ENOENT;

        return 0;
}

int sd_dhcp_lease_get_dns(sd_dhcp_lease *lease, struct in_addr **addr, size_t *addr_size) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(addr_size, -EINVAL);

        if (lease->dns_size) {
                *addr_size = lease->dns_size;
                *addr = lease->dns;
        } else
                return -ENOENT;

        return 0;
}

int sd_dhcp_lease_get_domainname(sd_dhcp_lease *lease, const char **domainname) {
        assert_return(lease, -EINVAL);
        assert_return(domainname, -EINVAL);

        if (lease->domainname)
                *domainname = lease->domainname;
        else
                return -ENOENT;

        return 0;
}

int sd_dhcp_lease_get_hostname(sd_dhcp_lease *lease, const char **hostname) {
        assert_return(lease, -EINVAL);
        assert_return(hostname, -EINVAL);

        if (lease->hostname)
                *hostname = lease->hostname;
        else
                return -ENOENT;

        return 0;
}

int sd_dhcp_lease_get_router(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        addr->s_addr = lease->router;

        return 0;
}

int sd_dhcp_lease_get_netmask(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        addr->s_addr = lease->subnet_mask;

        return 0;
}

sd_dhcp_lease *sd_dhcp_lease_ref(sd_dhcp_lease *lease) {
        if (lease)
                assert_se(REFCNT_INC(lease->n_ref) >= 2);

        return lease;
}

sd_dhcp_lease *sd_dhcp_lease_unref(sd_dhcp_lease *lease) {
        if (lease && REFCNT_DEC(lease->n_ref) <= 0) {
                free(lease->hostname);
                free(lease->domainname);
                free(lease->dns);
                free(lease);
        }

        return NULL;
}

int dhcp_lease_parse_options(uint8_t code, uint8_t len, const uint8_t *option,
                              void *user_data) {
        sd_dhcp_lease *lease = user_data;
        be32_t val;

        switch(code) {

        case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                if (len == 4) {
                        memcpy(&val, option, 4);
                        lease->lifetime = be32toh(val);
                }

                break;

        case DHCP_OPTION_SERVER_IDENTIFIER:
                if (len >= 4)
                        memcpy(&lease->server_address, option, 4);

                break;

        case DHCP_OPTION_SUBNET_MASK:
                if (len >= 4)
                        memcpy(&lease->subnet_mask, option, 4);

                break;

        case DHCP_OPTION_ROUTER:
                if (len >= 4)
                        memcpy(&lease->router, option, 4);

                break;

        case DHCP_OPTION_DOMAIN_NAME_SERVER:
                if (len && !(len % 4)) {
                        unsigned i;

                        lease->dns_size = len / 4;

                        free(lease->dns);
                        lease->dns = new0(struct in_addr, lease->dns_size);
                        if (!lease->dns)
                                return -ENOMEM;

                        for (i = 0; i < lease->dns_size; i++) {
                                memcpy(&lease->dns[i].s_addr, option + 4 * i, 4);
                        }
                }

                break;

        case DHCP_OPTION_INTERFACE_MTU:
                if (len >= 2) {
                        be16_t mtu;

                        memcpy(&mtu, option, 2);
                        lease->mtu = be16toh(mtu);

                        if (lease->mtu < 68)
                                lease->mtu = 0;
                }

                break;

        case DHCP_OPTION_DOMAIN_NAME:
                if (len >= 1) {
                        free(lease->domainname);
                        lease->domainname = strndup((const char *)option, len);
                }

                break;

        case DHCP_OPTION_HOST_NAME:
                if (len >= 1) {
                        free(lease->hostname);
                        lease->hostname = strndup((const char *)option, len);
                }

                break;

        case DHCP_OPTION_RENEWAL_T1_TIME:
                if (len == 4) {
                        memcpy(&val, option, 4);
                        lease->t1 = be32toh(val);
                }

                break;

        case DHCP_OPTION_REBINDING_T2_TIME:
                if (len == 4) {
                        memcpy(&val, option, 4);
                        lease->t2 = be32toh(val);
                }

                break;
        }

        return 0;
}

int dhcp_lease_new(sd_dhcp_lease **ret) {
        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;

        lease = new0(sd_dhcp_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->n_ref = REFCNT_INIT;

        *ret = lease;
        lease = NULL;

        return 0;
}
