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
#include <arpa/inet.h>

#include "fileio.h"
#include "unaligned.h"
#include "in-addr-util.h"
#include "hostname-util.h"
#include "dns-domain.h"
#include "network-internal.h"
#include "dhcp-protocol.h"
#include "dhcp-lease-internal.h"
#include "sd-dhcp-lease.h"

int sd_dhcp_lease_get_address(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->address == 0)
                return -ENODATA;

        addr->s_addr = lease->address;
        return 0;
}

int sd_dhcp_lease_get_broadcast(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (!lease->have_broadcast)
                return -ENODATA;

        addr->s_addr = lease->broadcast;
        return 0;
}

int sd_dhcp_lease_get_lifetime(sd_dhcp_lease *lease, uint32_t *lifetime) {
        assert_return(lease, -EINVAL);
        assert_return(lifetime, -EINVAL);

        if (lease->lifetime <= 0)
                return -ENODATA;

        *lifetime = lease->lifetime;
        return 0;
}

int sd_dhcp_lease_get_t1(sd_dhcp_lease *lease, uint32_t *t1) {
        assert_return(lease, -EINVAL);
        assert_return(t1, -EINVAL);

        if (lease->t1 <= 0)
                return -ENODATA;

        *t1 = lease->t1;
        return 0;
}

int sd_dhcp_lease_get_t2(sd_dhcp_lease *lease, uint32_t *t2) {
        assert_return(lease, -EINVAL);
        assert_return(t2, -EINVAL);

        if (lease->t2 <= 0)
                return -ENODATA;

        *t2 = lease->t2;
        return 0;
}

int sd_dhcp_lease_get_mtu(sd_dhcp_lease *lease, uint16_t *mtu) {
        assert_return(lease, -EINVAL);
        assert_return(mtu, -EINVAL);

        if (lease->mtu <= 0)
                return -ENODATA;

        *mtu = lease->mtu;
        return 0;
}

int sd_dhcp_lease_get_dns(sd_dhcp_lease *lease, const struct in_addr **addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->dns_size <= 0)
                return -ENODATA;

        *addr = lease->dns;
        return (int) lease->dns_size;
}

int sd_dhcp_lease_get_ntp(sd_dhcp_lease *lease, const struct in_addr **addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->ntp_size <= 0)
                return -ENODATA;

        *addr = lease->ntp;
        return (int) lease->ntp_size;
}

int sd_dhcp_lease_get_domainname(sd_dhcp_lease *lease, const char **domainname) {
        assert_return(lease, -EINVAL);
        assert_return(domainname, -EINVAL);

        if (!lease->domainname)
                return -ENODATA;

        *domainname = lease->domainname;
        return 0;
}

int sd_dhcp_lease_get_hostname(sd_dhcp_lease *lease, const char **hostname) {
        assert_return(lease, -EINVAL);
        assert_return(hostname, -EINVAL);

        if (!lease->hostname)
                return -ENODATA;

        *hostname = lease->hostname;
        return 0;
}

int sd_dhcp_lease_get_root_path(sd_dhcp_lease *lease, const char **root_path) {
        assert_return(lease, -EINVAL);
        assert_return(root_path, -EINVAL);

        if (!lease->root_path)
                return -ENODATA;

        *root_path = lease->root_path;
        return 0;
}

int sd_dhcp_lease_get_router(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->router == 0)
                return -ENODATA;

        addr->s_addr = lease->router;
        return 0;
}

int sd_dhcp_lease_get_netmask(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (!lease->have_subnet_mask)
                return -ENODATA;

        addr->s_addr = lease->subnet_mask;
        return 0;
}

int sd_dhcp_lease_get_server_identifier(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->server_address == 0)
                return -ENODATA;

        addr->s_addr = lease->server_address;
        return 0;
}

int sd_dhcp_lease_get_next_server(sd_dhcp_lease *lease, struct in_addr *addr) {
        assert_return(lease, -EINVAL);
        assert_return(addr, -EINVAL);

        if (lease->next_server == 0)
                return -ENODATA;

        addr->s_addr = lease->next_server;
        return 0;
}

int sd_dhcp_lease_get_routes(sd_dhcp_lease *lease, struct sd_dhcp_route **routes) {
        assert_return(lease, -EINVAL);
        assert_return(routes, -EINVAL);

        if (lease->static_route_size <= 0)
                return -ENODATA;

        *routes = lease->static_route;
        return (int) lease->static_route_size;
}

int sd_dhcp_lease_get_vendor_specific(sd_dhcp_lease *lease, const void **data, size_t *data_len) {
        assert_return(lease, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(data_len, -EINVAL);

        if (lease->vendor_specific_len <= 0)
                return -ENODATA;

        *data = lease->vendor_specific;
        *data_len = lease->vendor_specific_len;
        return 0;
}

sd_dhcp_lease *sd_dhcp_lease_ref(sd_dhcp_lease *lease) {

        if (!lease)
                return NULL;

        assert(lease->n_ref >= 1);
        lease->n_ref++;

        return lease;
}

sd_dhcp_lease *sd_dhcp_lease_unref(sd_dhcp_lease *lease) {

        if (!lease)
                return NULL;

        assert(lease->n_ref >= 1);
        lease->n_ref--;

        if (lease->n_ref > 0)
                return NULL;

        while (lease->private_options) {
                struct sd_dhcp_raw_option *option = lease->private_options;

                LIST_REMOVE(options, lease->private_options, option);

                free(option->data);
                free(option);
        }

        free(lease->hostname);
        free(lease->domainname);
        free(lease->dns);
        free(lease->ntp);
        free(lease->static_route);
        free(lease->client_id);
        free(lease->vendor_specific);
        free(lease);

        return NULL;
}

static int lease_parse_u32(const uint8_t *option, size_t len, uint32_t *ret, uint32_t min) {
        assert(option);
        assert(ret);

        if (len != 4)
                return -EINVAL;

        *ret = unaligned_read_be32((be32_t*) option);
        if (*ret < min)
                *ret = min;

        return 0;
}

static int lease_parse_u16(const uint8_t *option, size_t len, uint16_t *ret, uint16_t min) {
        assert(option);
        assert(ret);

        if (len != 2)
                return -EINVAL;

        *ret = unaligned_read_be16((be16_t*) option);
        if (*ret < min)
                *ret = min;

        return 0;
}

static int lease_parse_be32(const uint8_t *option, size_t len, be32_t *ret) {
        assert(option);
        assert(ret);

        if (len != 4)
                return -EINVAL;

        memcpy(ret, option, 4);
        return 0;
}

static int lease_parse_string(const uint8_t *option, size_t len, char **ret) {
        assert(option);
        assert(ret);

        if (len <= 0)
                *ret = mfree(*ret);
        else {
                char *string;

                if (memchr(option, 0, len))
                        return -EINVAL;

                string = strndup((const char *)option, len);
                if (!string)
                        return -ENOMEM;

                free(*ret);
                *ret = string;
        }

        return 0;
}

static int lease_parse_in_addrs(const uint8_t *option, size_t len, struct in_addr **ret, size_t *n_ret) {
        assert(option);
        assert(ret);
        assert(n_ret);

        if (len <= 0) {
                *ret = mfree(*ret);
                *n_ret = 0;
        } else {
                size_t n_addresses;
                struct in_addr *addresses;

                if (len % 4 != 0)
                        return -EINVAL;

                n_addresses = len / 4;

                addresses = newdup(struct in_addr, option, n_addresses);
                if (!addresses)
                        return -ENOMEM;

                free(*ret);
                *ret = addresses;
                *n_ret = n_addresses;
        }

        return 0;
}

static int lease_parse_routes(
                const uint8_t *option, size_t len,
                struct sd_dhcp_route **routes, size_t *routes_size, size_t *routes_allocated) {

        struct in_addr addr;

        assert(option || len <= 0);
        assert(routes);
        assert(routes_size);
        assert(routes_allocated);

        if (len <= 0)
                return 0;

        if (len % 8 != 0)
                return -EINVAL;

        if (!GREEDY_REALLOC(*routes, *routes_allocated, *routes_size + (len / 8)))
                return -ENOMEM;

        while (len >= 8) {
                struct sd_dhcp_route *route = *routes + *routes_size;
                int r;

                r = in_addr_default_prefixlen((struct in_addr*) option, &route->dst_prefixlen);
                if (r < 0) {
                        log_debug("Failed to determine destination prefix length from class based IP, ignoring");
                        continue;
                }

                assert_se(lease_parse_be32(option, 4, &addr.s_addr) >= 0);
                route->dst_addr = inet_makeaddr(inet_netof(addr), 0);
                option += 4;

                assert_se(lease_parse_be32(option, 4, &route->gw_addr.s_addr) >= 0);
                option += 4;

                len -= 8;
                (*routes_size)++;
        }

        return 0;
}

/* parses RFC3442 Classless Static Route Option */
static int lease_parse_classless_routes(
                const uint8_t *option, size_t len,
                struct sd_dhcp_route **routes, size_t *routes_size, size_t *routes_allocated) {

        assert(option || len <= 0);
        assert(routes);
        assert(routes_size);
        assert(routes_allocated);

        if (len <= 0)
                return 0;

        /* option format: (subnet-mask-width significant-subnet-octets gateway-ip)*  */

        while (len > 0) {
                uint8_t dst_octets;
                struct sd_dhcp_route *route;

                if (!GREEDY_REALLOC(*routes, *routes_allocated, *routes_size + 1))
                        return -ENOMEM;

                route = *routes + *routes_size;

                dst_octets = (*option == 0 ? 0 : ((*option - 1) / 8) + 1);
                route->dst_prefixlen = *option;
                option++;
                len--;

                /* can't have more than 4 octets in IPv4 */
                if (dst_octets > 4 || len < dst_octets)
                        return -EINVAL;

                route->dst_addr.s_addr = 0;
                memcpy(&route->dst_addr.s_addr, option, dst_octets);
                option += dst_octets;
                len -= dst_octets;

                if (len < 4)
                        return -EINVAL;

                lease_parse_be32(option, 4, &route->gw_addr.s_addr);
                option += 4;
                len -= 4;

                (*routes_size)++;
        }

        return 0;
}

int dhcp_lease_parse_options(uint8_t code, uint8_t len, const void *option, void *userdata) {
        sd_dhcp_lease *lease = userdata;
        int r;

        assert(lease);

        switch(code) {

        case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                r = lease_parse_u32(option, len, &lease->lifetime, 1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse lease time, ignoring: %m");

                break;

        case DHCP_OPTION_SERVER_IDENTIFIER:
                r = lease_parse_be32(option, len, &lease->server_address);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse server identifier, ignoring: %m");

                break;

        case DHCP_OPTION_SUBNET_MASK:
                r = lease_parse_be32(option, len, &lease->subnet_mask);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse subnet mask, ignoring: %m");
                else
                        lease->have_subnet_mask = true;
                break;

        case DHCP_OPTION_BROADCAST:
                r = lease_parse_be32(option, len, &lease->broadcast);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse broadcast address, ignoring: %m");
                else
                        lease->have_broadcast = true;
                break;

        case DHCP_OPTION_ROUTER:
                if (len >= 4) {
                        r = lease_parse_be32(option, 4, &lease->router);
                        if (r < 0)
                                log_debug_errno(r, "Failed to parse router address, ignoring: %m");
                }
                break;

        case DHCP_OPTION_DOMAIN_NAME_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->dns, &lease->dns_size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse DNS server, ignoring: %m");
                break;

        case DHCP_OPTION_NTP_SERVER:
                r = lease_parse_in_addrs(option, len, &lease->ntp, &lease->ntp_size);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse NTP server, ignoring: %m");
                break;

        case DHCP_OPTION_STATIC_ROUTE:
                r = lease_parse_routes(option, len, &lease->static_route, &lease->static_route_size, &lease->static_route_allocated);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse static routes, ignoring: %m");
                break;

        case DHCP_OPTION_INTERFACE_MTU:
                r = lease_parse_u16(option, len, &lease->mtu, 68);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse MTU, ignoring: %m");
                break;

        case DHCP_OPTION_DOMAIN_NAME: {
                _cleanup_free_ char *domainname = NULL, *normalized = NULL;

                r = lease_parse_string(option, len, &domainname);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse domain name, ignoring: %m");
                        return 0;
                }

                r = dns_name_normalize(domainname, &normalized);
                if (r < 0) {
                        log_debug_errno(r, "Failed to normalize domain name '%s': %m", domainname);
                        return 0;
                }

                if (is_localhost(normalized)) {
                        log_debug_errno(r, "Detected 'localhost' as suggested domain name, ignoring.");
                        break;
                }

                free(lease->domainname);
                lease->domainname = normalized;
                normalized = NULL;

                break;
        }

        case DHCP_OPTION_HOST_NAME: {
                _cleanup_free_ char *hostname = NULL, *normalized = NULL;

                r = lease_parse_string(option, len, &hostname);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse host name, ignoring: %m");
                        return 0;
                }

                r = dns_name_normalize(hostname, &normalized);
                if (r < 0) {
                        log_debug_errno(r, "Failed to normalize host name '%s', ignoring: %m", hostname);
                        return 0;
                }

                if (is_localhost(normalized)) {
                        log_debug_errno(r, "Detected 'localhost' as suggested host name, ignoring.");
                        return 0;
                }

                free(lease->hostname);
                lease->hostname = normalized;
                normalized = NULL;

                break;
        }

        case DHCP_OPTION_ROOT_PATH:
                r = lease_parse_string(option, len, &lease->root_path);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse root path, ignoring: %m");
                break;

        case DHCP_OPTION_RENEWAL_T1_TIME:
                r = lease_parse_u32(option, len, &lease->t1, 1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T1 time, ignoring: %m");
                break;

        case DHCP_OPTION_REBINDING_T2_TIME:
                r = lease_parse_u32(option, len, &lease->t2, 1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T2 time, ignoring: %m");
                break;

        case DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
                r = lease_parse_classless_routes(
                                option, len,
                                &lease->static_route,
                                &lease->static_route_size,
                                &lease->static_route_allocated);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse classless routes, ignoring: %m");
                break;

        case DHCP_OPTION_NEW_TZDB_TIMEZONE: {
                _cleanup_free_ char *tz = NULL;

                r = lease_parse_string(option, len, &tz);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse timezone option, ignoring: %m");
                        return 0;
                }

                if (!timezone_is_valid(tz)) {
                        log_debug_errno(r, "Timezone is not valid, ignoring: %m");
                        return 0;
                }

                free(lease->timezone);
                lease->timezone = tz;
                tz = NULL;

                break;
        }

        case DHCP_OPTION_VENDOR_SPECIFIC:

                if (len <= 0)
                        lease->vendor_specific = mfree(lease->vendor_specific);
                else {
                        void *p;

                        p = memdup(option, len);
                        if (!p)
                                return -ENOMEM;

                        free(lease->vendor_specific);
                        lease->vendor_specific = p;
                }

                lease->vendor_specific_len = len;
                break;

        case DHCP_OPTION_PRIVATE_BASE ... DHCP_OPTION_PRIVATE_LAST:
                r = dhcp_lease_insert_private_option(lease, code, option, len);
                if (r < 0)
                        return r;

                break;

        default:
                log_debug("Ignoring option DHCP option %i while parsing.", code);
                break;
        }

        return 0;
}

int dhcp_lease_insert_private_option(sd_dhcp_lease *lease, uint8_t tag, const void *data, uint8_t len) {
        struct sd_dhcp_raw_option *cur, *option;

        assert(lease);

        LIST_FOREACH(options, cur, lease->private_options) {
                if (tag < cur->tag)
                        break;
                if (tag == cur->tag) {
                        log_debug("Ignoring duplicate option, tagged %i.", tag);
                        return 0;
                }
        }

        option = new(struct sd_dhcp_raw_option, 1);
        if (!option)
                return -ENOMEM;

        option->tag = tag;
        option->length = len;
        option->data = memdup(data, len);
        if (!option->data) {
                free(option);
                return -ENOMEM;
        }

        LIST_INSERT_BEFORE(options, lease->private_options, cur, option);
        return 0;
}

int dhcp_lease_new(sd_dhcp_lease **ret) {
        sd_dhcp_lease *lease;

        lease = new0(sd_dhcp_lease, 1);
        if (!lease)
                return -ENOMEM;

        lease->router = INADDR_ANY;
        lease->n_ref = 1;

        *ret = lease;
        return 0;
}

int dhcp_lease_save(sd_dhcp_lease *lease, const char *lease_file) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct sd_dhcp_raw_option *option;
        struct in_addr address;
        const struct in_addr *addresses;
        const void *client_id, *data;
        size_t client_id_len, data_len;
        const char *string;
        uint16_t mtu;
        struct sd_dhcp_route *routes;
        uint32_t t1, t2, lifetime;
        int r;

        assert(lease);
        assert(lease_file);

        r = fopen_temporary(lease_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n");

        r = sd_dhcp_lease_get_address(lease, &address);
        if (r >= 0)
                fprintf(f, "ADDRESS=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_netmask(lease, &address);
        if (r >= 0)
                fprintf(f, "NETMASK=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_router(lease, &address);
        if (r >= 0)
                fprintf(f, "ROUTER=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_server_identifier(lease, &address);
        if (r >= 0)
                fprintf(f, "SERVER_ADDRESS=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_next_server(lease, &address);
        if (r >= 0)
                fprintf(f, "NEXT_SERVER=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_broadcast(lease, &address);
        if (r >= 0)
                fprintf(f, "BROADCAST=%s\n", inet_ntoa(address));

        r = sd_dhcp_lease_get_mtu(lease, &mtu);
        if (r >= 0)
                fprintf(f, "MTU=%" PRIu16 "\n", mtu);

        r = sd_dhcp_lease_get_t1(lease, &t1);
        if (r >= 0)
                fprintf(f, "T1=%" PRIu32 "\n", t1);

        r = sd_dhcp_lease_get_t2(lease, &t2);
        if (r >= 0)
                fprintf(f, "T2=%" PRIu32 "\n", t2);

        r = sd_dhcp_lease_get_lifetime(lease, &lifetime);
        if (r >= 0)
                fprintf(f, "LIFETIME=%" PRIu32 "\n", lifetime);

        r = sd_dhcp_lease_get_dns(lease, &addresses);
        if (r > 0) {
                fputs("DNS=", f);
                serialize_in_addrs(f, addresses, r);
                fputs("\n", f);
        }

        r = sd_dhcp_lease_get_ntp(lease, &addresses);
        if (r > 0) {
                fputs("NTP=", f);
                serialize_in_addrs(f, addresses, r);
                fputs("\n", f);
        }

        r = sd_dhcp_lease_get_domainname(lease, &string);
        if (r >= 0)
                fprintf(f, "DOMAINNAME=%s\n", string);

        r = sd_dhcp_lease_get_hostname(lease, &string);
        if (r >= 0)
                fprintf(f, "HOSTNAME=%s\n", string);

        r = sd_dhcp_lease_get_root_path(lease, &string);
        if (r >= 0)
                fprintf(f, "ROOT_PATH=%s\n", string);

        r = sd_dhcp_lease_get_routes(lease, &routes);
        if (r > 0)
                serialize_dhcp_routes(f, "ROUTES", routes, r);

        r = sd_dhcp_lease_get_timezone(lease, &string);
        if (r >= 0)
                fprintf(f, "TIMEZONE=%s\n", string);

        r = sd_dhcp_lease_get_client_id(lease, &client_id, &client_id_len);
        if (r >= 0) {
                _cleanup_free_ char *client_id_hex;

                client_id_hex = hexmem(client_id, client_id_len);
                if (!client_id_hex) {
                        r = -ENOMEM;
                        goto fail;
                }
                fprintf(f, "CLIENTID=%s\n", client_id_hex);
        }

        r = sd_dhcp_lease_get_vendor_specific(lease, &data, &data_len);
        if (r >= 0) {
                _cleanup_free_ char *option_hex = NULL;

                option_hex = hexmem(data, data_len);
                if (!option_hex) {
                        r = -ENOMEM;
                        goto fail;
                }
                fprintf(f, "VENDOR_SPECIFIC=%s\n", option_hex);
        }

        LIST_FOREACH(options, option, lease->private_options) {
                char key[strlen("OPTION_000")+1];

                snprintf(key, sizeof(key), "OPTION_%"PRIu8, option->tag);
                r = serialize_dhcp_option(f, key, option->data, option->length);
                if (r < 0)
                        goto fail;
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, lease_file) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        if (temp_path)
                (void) unlink(temp_path);

        return log_error_errno(r, "Failed to save lease data %s: %m", lease_file);
}

int dhcp_lease_load(sd_dhcp_lease **ret, const char *lease_file) {

        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
        _cleanup_free_ char
                *address = NULL,
                *router = NULL,
                *netmask = NULL,
                *server_address = NULL,
                *next_server = NULL,
                *broadcast = NULL,
                *dns = NULL,
                *ntp = NULL,
                *mtu = NULL,
                *routes = NULL,
                *client_id_hex = NULL,
                *vendor_specific_hex = NULL,
                *lifetime = NULL,
                *t1 = NULL,
                *t2 = NULL,
                *options[DHCP_OPTION_PRIVATE_LAST - DHCP_OPTION_PRIVATE_BASE + 1] = {};

        int r, i;

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
                           "BROADCAST", &broadcast,
                           "DNS", &dns,
                           "NTP", &ntp,
                           "MTU", &mtu,
                           "DOMAINNAME", &lease->domainname,
                           "HOSTNAME", &lease->hostname,
                           "ROOT_PATH", &lease->root_path,
                           "ROUTES", &routes,
                           "CLIENTID", &client_id_hex,
                           "TIMEZONE", &lease->timezone,
                           "VENDOR_SPECIFIC", &vendor_specific_hex,
                           "LIFETIME", &lifetime,
                           "T1", &t1,
                           "T2", &t2,
                           "OPTION_224", &options[0],
                           "OPTION_225", &options[1],
                           "OPTION_226", &options[2],
                           "OPTION_227", &options[3],
                           "OPTION_228", &options[4],
                           "OPTION_229", &options[5],
                           "OPTION_230", &options[6],
                           "OPTION_231", &options[7],
                           "OPTION_232", &options[8],
                           "OPTION_233", &options[9],
                           "OPTION_234", &options[10],
                           "OPTION_235", &options[11],
                           "OPTION_236", &options[12],
                           "OPTION_237", &options[13],
                           "OPTION_238", &options[14],
                           "OPTION_239", &options[15],
                           "OPTION_240", &options[16],
                           "OPTION_241", &options[17],
                           "OPTION_242", &options[18],
                           "OPTION_243", &options[19],
                           "OPTION_244", &options[20],
                           "OPTION_245", &options[21],
                           "OPTION_246", &options[22],
                           "OPTION_247", &options[23],
                           "OPTION_248", &options[24],
                           "OPTION_249", &options[25],
                           "OPTION_250", &options[26],
                           "OPTION_251", &options[27],
                           "OPTION_252", &options[28],
                           "OPTION_253", &options[29],
                           "OPTION_254", &options[30],
                           NULL);
        if (r < 0)
                return r;

        if (address) {
                r = inet_pton(AF_INET, address, &lease->address);
                if (r <= 0)
                        log_debug_errno(errno, "Failed to parse address %s, ignoring: %m", address);
        }

        if (router) {
                r = inet_pton(AF_INET, router, &lease->router);
                if (r <= 0)
                        log_debug_errno(errno, "Failed to parse router %s, ignoring: %m", router);
        }

        if (netmask) {
                r = inet_pton(AF_INET, netmask, &lease->subnet_mask);
                if (r <= 0)
                        log_debug_errno(errno, "Failed to parse netmask %s, ignoring: %m", netmask);
                else
                        lease->have_subnet_mask = true;
        }

        if (server_address) {
                r = inet_pton(AF_INET, server_address, &lease->server_address);
                if (r <= 0)
                        log_debug_errno(errno, "Failed to parse netmask %s, ignoring: %m", server_address);
        }

        if (next_server) {
                r = inet_pton(AF_INET, next_server, &lease->next_server);
                if (r <= 0)
                        log_debug_errno(errno, "Failed to parse next server %s, ignoring: %m", next_server);
        }

        if (broadcast) {
                r = inet_pton(AF_INET, broadcast, &lease->broadcast);
                if (r <= 0)
                        log_debug_errno(errno, "Failed to parse broadcast address %s, ignoring: %m", broadcast);
                else
                        lease->have_broadcast = true;
        }

        if (dns) {
                r = deserialize_in_addrs(&lease->dns, dns);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize DNS servers %s, ignoring: %m", dns);
                else
                        lease->dns_size = r;
        }

        if (ntp) {
                r = deserialize_in_addrs(&lease->ntp, ntp);
                if (r < 0)
                        log_debug_errno(r, "Failed to deserialize NTP servers %s, ignoring: %m", ntp);
                else
                        lease->ntp_size = r;
        }

        if (mtu) {
                r = safe_atou16(mtu, &lease->mtu);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse MTU %s, ignoring: %m", mtu);
        }

        if (routes) {
                r = deserialize_dhcp_routes(
                                &lease->static_route,
                                &lease->static_route_size,
                                &lease->static_route_allocated,
                                routes);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse DHCP routes %s, ignoring: %m", routes);
        }

        if (lifetime) {
                r = safe_atou32(lifetime, &lease->lifetime);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse lifetime %s, ignoring: %m", lifetime);
        }

        if (t1) {
                r = safe_atou32(t1, &lease->t1);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T1 %s, ignoring: %m", t1);
        }

        if (t2) {
                r = safe_atou32(t2, &lease->t2);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse T2 %s, ignoring: %m", t2);
        }

        if (client_id_hex) {
                r = deserialize_dhcp_option(&lease->client_id, &lease->client_id_len, client_id_hex);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse client ID %s, ignoring: %m", client_id_hex);
        }

        if (vendor_specific_hex) {
                r = deserialize_dhcp_option(&lease->vendor_specific, &lease->vendor_specific_len, vendor_specific_hex);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse vendor specific data %s, ignoring: %m", vendor_specific_hex);
        }

        for (i = 0; i <= DHCP_OPTION_PRIVATE_LAST - DHCP_OPTION_PRIVATE_BASE; i++) {
                _cleanup_free_ void *data = NULL;
                size_t len;

                if (!options[i])
                        continue;

                r = deserialize_dhcp_option(&data, &len, options[i]);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse private DHCP option %s, ignoring: %m", options[i]);
                        continue;
                }

                r = dhcp_lease_insert_private_option(lease, DHCP_OPTION_PRIVATE_BASE + i, data, len);
                if (r < 0)
                        return r;
        }

        *ret = lease;
        lease = NULL;

        return 0;
}

int dhcp_lease_set_default_subnet_mask(sd_dhcp_lease *lease) {
        struct in_addr address, mask;
        int r;

        assert(lease);

        if (lease->address == 0)
                return -ENODATA;

        address.s_addr = lease->address;

        /* fall back to the default subnet masks based on address class */
        r = in_addr_default_subnet_mask(&address, &mask);
        if (r < 0)
                return r;

        lease->subnet_mask = mask.s_addr;
        lease->have_subnet_mask = true;

        return 0;
}

int sd_dhcp_lease_get_client_id(sd_dhcp_lease *lease, const void **client_id, size_t *client_id_len) {
        assert_return(lease, -EINVAL);
        assert_return(client_id, -EINVAL);
        assert_return(client_id_len, -EINVAL);

        if (!lease->client_id)
                return -ENODATA;

        *client_id = lease->client_id;
        *client_id_len = lease->client_id_len;

        return 0;
}

int dhcp_lease_set_client_id(sd_dhcp_lease *lease, const void *client_id, size_t client_id_len) {
        assert_return(lease, -EINVAL);
        assert_return(client_id || client_id_len <= 0, -EINVAL);

        if (client_id_len <= 0)
                lease->client_id = mfree(lease->client_id);
        else {
                void *p;

                p = memdup(client_id, client_id_len);
                if (!p)
                        return -ENOMEM;

                free(lease->client_id);
                lease->client_id = p;
                lease->client_id_len = client_id_len;
        }

        return 0;
}

int sd_dhcp_lease_get_timezone(sd_dhcp_lease *lease, const char **tz) {
        assert_return(lease, -EINVAL);
        assert_return(tz, -EINVAL);

        if (!lease->timezone)
                return -ENODATA;

        *tz = lease->timezone;
        return 0;
}
