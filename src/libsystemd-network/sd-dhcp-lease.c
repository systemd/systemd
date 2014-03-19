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
#include <arpa/inet.h>
#include <sys/param.h>

#include "util.h"
#include "list.h"
#include "mkdir.h"
#include "fileio.h"

#include "dhcp-protocol.h"
#include "dhcp-internal.h"
#include "dhcp-lease-internal.h"
#include "sd-dhcp-lease.h"
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

int sd_dhcp_lease_get_root_path(sd_dhcp_lease *lease, const char **root_path) {
        assert_return(lease, -EINVAL);
        assert_return(root_path, -EINVAL);

        if (lease->root_path)
                *root_path = lease->root_path;
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

int sd_dhcp_lease_get_server_identifier(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        addr->s_addr = lease->server_address;

        return 0;
}

int sd_dhcp_lease_get_next_server(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        addr->s_addr = lease->next_server;

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

        case DHCP_OPTION_ROOT_PATH:
                if (len >= 1) {
                        free(lease->root_path);
                        lease->root_path = strndup((const char *)option, len);
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

int dhcp_lease_save(sd_dhcp_lease *lease, const char *lease_file) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        char buf[INET_ADDRSTRLEN];
        struct in_addr address;
        const char *string;
        uint16_t mtu;
        int r;

        assert(lease);
        assert(lease_file);

        r = fopen_temporary(lease_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r < 0)
                goto finish;

        string = inet_ntop(AF_INET, &address, buf, INET_ADDRSTRLEN);
        if (!string) {
                r = -errno;
                goto finish;
        }

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "ADDRESS=%s\n", string);

        r = sd_dhcp_lease_get_router(lease, &address);
        if (r < 0)
                goto finish;

        string = inet_ntop(AF_INET, &address, buf, INET_ADDRSTRLEN);
        if (!string) {
                r = -errno;
                goto finish;
        }

        fprintf(f,
                "ROUTER=%s\n", string);

        r = sd_dhcp_lease_get_netmask(lease, &address);
        if (r < 0)
                goto finish;

        string = inet_ntop(AF_INET, &address, buf, INET_ADDRSTRLEN);
        if (!string) {
                r = -errno;
                goto finish;
        }

        fprintf(f,
                "NETMASK=%s\n", string);

        r = sd_dhcp_lease_get_server_identifier(lease, &address);
        if (r >= 0) {
                string = inet_ntop(AF_INET, &address, buf, INET_ADDRSTRLEN);
                if (!string) {
                        r = -errno;
                        goto finish;
                }

                fprintf(f,
                        "SERVER_ADDRESS=%s\n", string);
        }

        r = sd_dhcp_lease_get_next_server(lease, &address);
        if (r >= 0) {
                string = inet_ntop(AF_INET, &address, buf, INET_ADDRSTRLEN);
                if (!string) {
                        r = -errno;
                        goto finish;
                }

                fprintf(f,
                        "NEXT_SERVER=%s\n", string);
        }

        r = sd_dhcp_lease_get_mtu(lease, &mtu);
        if (r >= 0)
                fprintf(f, "MTU=%" PRIu16 "\n", mtu);

/* TODO: DNS. See resolv.conf writing in network-manager.c */

        r = sd_dhcp_lease_get_domainname(lease, &string);
        if (r >= 0)
                fprintf(f, "DOMAINNAME=%s\n", string);

        r = sd_dhcp_lease_get_hostname(lease, &string);
        if (r >= 0)
                fprintf(f, "HOSTNAME=%s\n", string);

        r = sd_dhcp_lease_get_root_path(lease, &string);
        if (r >= 0)
                fprintf(f, "ROOT_PATH=%s\n", string);

        r = 0;

        fflush(f);

        if (ferror(f) || rename(temp_path, lease_file) < 0) {
                r = -errno;
                unlink(lease_file);
                unlink(temp_path);
        }

finish:
        if (r < 0)
                log_error("Failed to save lease data %s: %s", lease_file, strerror(-r));

        return r;
}

int dhcp_lease_load(const char *lease_file, sd_dhcp_lease **ret) {
        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
        _cleanup_free_ char *address = NULL, *router = NULL, *netmask = NULL,
                            *server_address = NULL, *next_server = NULL,
                            *mtu = NULL;
        struct in_addr addr;
        int r;

        assert(lease_file);
        assert(ret);

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        r = parse_env_file(lease_file, NEWLINE,
                           "ADDRESS", &address,
                           "ROUTER", &router,
                           "NETMASK", &netmask,
                           "SERVER_IDENTIFIER", &server_address,
                           "NEXT_SERVER", &next_server,
                           "MTU", &mtu,
                           "DOMAINNAME", &lease->domainname,
                           "HOSTNAME", &lease->hostname,
                           "ROOT_PATH", &lease->root_path,
                           NULL);
        if (r < 0) {
                if (r == -ENOENT)
                        return 0;

                log_error("Failed to read %s: %s", lease_file, strerror(-r));
                return r;
        }

        r = inet_pton(AF_INET, address, &addr);
        if (r < 0)
                return r;

        lease->address = addr.s_addr;

        r = inet_pton(AF_INET, router, &addr);
        if (r < 0)
                return r;

        lease->router = addr.s_addr;

        r = inet_pton(AF_INET, netmask, &addr);
        if (r < 0)
                return r;

        lease->subnet_mask = addr.s_addr;

        if (server_address) {
                r = inet_pton(AF_INET, server_address, &addr);
                if (r < 0)
                        return r;

                lease->server_address = addr.s_addr;
        }

        if (next_server) {
                r = inet_pton(AF_INET, next_server, &addr);
                if (r < 0)
                        return r;

                lease->next_server = addr.s_addr;
        }

        if (mtu) {
                uint16_t u;
                if (sscanf(mtu, "%" SCNu16, &u) > 0)
                        lease->mtu = u;
        }

        *ret = lease;
        lease = NULL;

        return 0;
}

int dhcp_lease_set_default_subnet_mask(sd_dhcp_lease *lease) {
        uint32_t address;

        assert(lease);
        assert(lease->address != INADDR_ANY);

        address = be32toh(lease->address);

        /* fall back to the default subnet masks based on address class */

        if ((address >> 31) == 0x0)
                /* class A, leading bits: 0 */
                lease->subnet_mask = htobe32(0xff000000);
        else if ((address >> 30) == 0x2)
                /* class B, leading bits 10 */
                lease->subnet_mask = htobe32(0xffff0000);
        else if ((address >> 29) == 0x6)
                /* class C, leading bits 110 */
                lease->subnet_mask = htobe32(0xffffff00);
        else
                /* class D or E, no default mask. give up */
                return -ERANGE;

        return 0;
}
