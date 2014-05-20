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
#include "network-internal.h"

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

int sd_dhcp_lease_get_ntp(sd_dhcp_lease *lease, struct in_addr **addr, size_t *addr_size) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(addr_size, -EINVAL);

        if (lease->ntp_size) {
                *addr_size = lease->ntp_size;
                *addr = lease->ntp;
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

        if (lease->router != INADDR_ANY)
                addr->s_addr = lease->router;
        else
                return -ENOENT;

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
                free(lease->ntp);
                free(lease);
        }

        return NULL;
}

static void lease_parse_u32(const uint8_t *option, size_t len, uint32_t *ret, uint32_t min) {
        be32_t val;

        assert(option);
        assert(ret);

        if (len == 4) {
                memcpy(&val, option, 4);
                *ret = be32toh(val);

                if (*ret < min)
                        *ret = min;
        }
}

static void lease_parse_s32(const uint8_t *option, size_t len, int32_t *ret) {
        lease_parse_u32(option, len, (uint32_t *)ret, 0);
}

static void lease_parse_u16(const uint8_t *option, size_t len, uint16_t *ret, uint16_t min) {
        be16_t val;

        assert(option);
        assert(ret);

        if (len == 2) {
                memcpy(&val, option, 2);
                *ret = be16toh(val);

                if (*ret < min)
                        *ret = min;
        }
}

static void lease_parse_be32(const uint8_t *option, size_t len, be32_t *ret) {
        assert(option);
        assert(ret);

        if (len == 4)
                memcpy(ret, option, 4);
}

static void lease_parse_bool(const uint8_t *option, size_t len, bool *ret) {
        assert(option);
        assert(ret);

        if (len == 1)
                *ret = !!(*option);
}

static void lease_parse_u8(const uint8_t *option, size_t len, uint8_t *ret, uint8_t min) {
        assert(option);
        assert(ret);

        if (len == 1) {
                *ret = *option;

                if (*ret < min)
                        *ret = min;
        }
}

static int lease_parse_string(const uint8_t *option, size_t len, char **ret) {
        assert(option);
        assert(ret);

        if (len >= 1) {
                char *string;

                string = strndup((const char *)option, len);
                if (!string)
                        return -errno;

                free(*ret);
                *ret = string;
        }

        return 0;
}

static int lease_parse_in_addrs_aux(const uint8_t *option, size_t len, struct in_addr **ret, size_t *ret_size, size_t mult) {
        assert(option);
        assert(ret);
        assert(ret_size);

        if (len && !(len % (4 * mult))) {
                size_t size;
                struct in_addr *addresses;

                size = len / 4;

                addresses = newdup(struct in_addr, option, size);
                if (!addresses)
                        return -ENOMEM;

                free(*ret);
                *ret = addresses;
                *ret_size = size;
        }

        return 0;
}

static int lease_parse_in_addrs(const uint8_t *option, size_t len, struct in_addr **ret, size_t *ret_size) {
        return lease_parse_in_addrs_aux(option, len, ret, ret_size, 1);
}

static int lease_parse_in_addrs_pairs(const uint8_t *option, size_t len, struct in_addr **ret, size_t *ret_size) {
        return lease_parse_in_addrs_aux(option, len, ret, ret_size, 2);
}

int dhcp_lease_parse_options(uint8_t code, uint8_t len, const uint8_t *option,
                              void *user_data) {
        sd_dhcp_lease *lease = user_data;
        int r;

        assert(lease);

        switch(code) {

        case DHCP_OPTION_TIME_OFFSET:
                lease_parse_s32(option, len, &lease->time_offset);

                break;

        case DHCP_OPTION_INTERFACE_MTU_AGING_TIMEOUT:
                lease_parse_u32(option, len, &lease->mtu_aging_timeout, 0);

                break;

        case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                lease_parse_u32(option, len, &lease->lifetime, 1);

                break;

        case DHCP_OPTION_SERVER_IDENTIFIER:
                lease_parse_be32(option, len, &lease->server_address);

                break;

        case DHCP_OPTION_SUBNET_MASK:
                lease_parse_be32(option, len, &lease->subnet_mask);

                break;

        case DHCP_OPTION_BROADCAST:
                lease_parse_be32(option, len, &lease->broadcast);

                break;

        case DHCP_OPTION_ROUTER:
                lease_parse_be32(option, len, &lease->router);

                break;

        case DHCP_OPTION_DOMAIN_NAME_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->dns, &lease->dns_size);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_NTP_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->ntp, &lease->ntp_size);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_POLICY_FILTER:
                r = lease_parse_in_addrs_pairs(option, len, &lease->policy_filter, &lease->policy_filter_size);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_STATIC_ROUTE:
                r = lease_parse_in_addrs_pairs(option, len, &lease->static_route, &lease->static_route_size);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_INTERFACE_MTU:
                lease_parse_u16(option, len, &lease->mtu, 68);

                break;

        case DHCP_OPTION_INTERFACE_MDR:
                lease_parse_u16(option, len, &lease->mdr, 576);

                break;

        case DHCP_OPTION_INTERFACE_TTL:
                lease_parse_u8(option, len, &lease->ttl, 1);

                break;

        case DHCP_OPTION_BOOT_FILE_SIZE:
                lease_parse_u16(option, len, &lease->boot_file_size, 0);

                break;

        case DHCP_OPTION_DOMAIN_NAME:
                r = lease_parse_string(option, len, &lease->domainname);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_HOST_NAME:
                r = lease_parse_string(option, len, &lease->hostname);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_ROOT_PATH:
                r = lease_parse_string(option, len, &lease->root_path);
                if (r < 0)
                        return r;

                break;

        case DHCP_OPTION_RENEWAL_T1_TIME:
                lease_parse_u32(option, len, &lease->t1, 1);

                break;

        case DHCP_OPTION_REBINDING_T2_TIME:
                lease_parse_u32(option, len, &lease->t2, 1);

                break;

        case DHCP_OPTION_ENABLE_IP_FORWARDING:
                lease_parse_bool(option, len, &lease->ip_forward);

                break;

        case DHCP_OPTION_ENABLE_IP_FORWARDING_NL:
                lease_parse_bool(option, len, &lease->ip_forward_non_local);

                break;
        }

        return 0;
}

int dhcp_lease_new(sd_dhcp_lease **ret) {
        sd_dhcp_lease *lease;

        lease = new0(sd_dhcp_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->router = INADDR_ANY;
        lease->n_ref = REFCNT_INIT;

        *ret = lease;
        return 0;
}

int dhcp_lease_save(sd_dhcp_lease *lease, const char *lease_file) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct in_addr address;
        struct in_addr *addresses;
        size_t addresses_size;
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

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "ADDRESS=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_netmask(lease, &address);
        if (r < 0)
                goto finish;

        fprintf(f, "NETMASK=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_router(lease, &address);
        if (r >= 0)
                fprintf(f, "ROUTER=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_server_identifier(lease, &address);
        if (r >= 0)
                fprintf(f, "SERVER_ADDRESS=%s\n",
                        inet_ntoa(address));

        r = sd_dhcp_lease_get_next_server(lease, &address);
        if (r >= 0)
                fprintf(f, "NEXT_SERVER=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_mtu(lease, &mtu);
        if (r >= 0)
                fprintf(f, "MTU=%" PRIu16 "\n", mtu);

        r = sd_dhcp_lease_get_dns(lease, &addresses, &addresses_size);
        if (r >= 0)
                serialize_in_addrs(f, "DNS", addresses, addresses_size);

        r = sd_dhcp_lease_get_ntp(lease, &addresses, &addresses_size);
        if (r >= 0)
                serialize_in_addrs(f, "NTP", addresses, addresses_size);

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
                            *dns = NULL, *ntp = NULL, *mtu = NULL;
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
                           "DNS", &dns,
                           "NTP", &ntp,
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

        if (router) {
                r = inet_pton(AF_INET, router, &addr);
                if (r < 0)
                        return r;

                lease->router = addr.s_addr;
        }

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

        if (dns) {
                r = deserialize_in_addrs(&lease->dns, &lease->dns_size, dns);
                if (r < 0)
                        return r;
        }

        if (ntp) {
                r = deserialize_in_addrs(&lease->ntp, &lease->ntp_size, dns);
                if (r < 0)
                        return r;
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
