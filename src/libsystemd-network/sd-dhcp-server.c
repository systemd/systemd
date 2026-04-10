/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include "sd-dhcp-server.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-request.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "network-common.h"
#include "path-util.h"
#include "socket-util.h"
#include "string-util.h"

#define DHCP_DEFAULT_LEASE_TIME_USEC USEC_PER_HOUR
#define DHCP_MAX_LEASE_TIME_USEC (USEC_PER_HOUR*12)

void dhcp_server_on_lease_change(sd_dhcp_server *server) {
        int r;

        assert(server);

        r = dhcp_server_save_leases(server);
        if (r < 0)
                log_dhcp_server_errno(server, r, "Failed to save leases, ignoring: %m");

        if (server->callback)
                server->callback(server, SD_DHCP_SERVER_EVENT_LEASE_CHANGED, server->callback_userdata);
}

/* configures the server's address and subnet, and optionally the pool's size and offset into the subnet
 * the whole pool must fit into the subnet, and may not contain the first (any) nor last (broadcast) address
 * moreover, the server's own address may be in the pool, and is in that case reserved in order not to
 * accidentally hand it out */
int sd_dhcp_server_configure_pool(
                sd_dhcp_server *server,
                const struct in_addr *address,
                unsigned char prefixlen,
                uint32_t offset,
                uint32_t size) {

        struct in_addr netmask_addr;
        be32_t netmask;
        uint32_t server_off, broadcast_off, size_max;

        assert_return(server, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(address->s_addr != INADDR_ANY, -EINVAL);
        assert_return(prefixlen <= 32, -ERANGE);

        assert_se(in4_addr_prefixlen_to_netmask(&netmask_addr, prefixlen));
        netmask = netmask_addr.s_addr;

        server_off = be32toh(address->s_addr & ~netmask);
        broadcast_off = be32toh(~netmask);

        /* the server address cannot be the subnet address */
        assert_return(server_off != 0, -ERANGE);

        /* nor the broadcast address */
        assert_return(server_off != broadcast_off, -ERANGE);

        /* 0 offset means we should set a default, we skip the first (subnet) address
           and take the next one */
        if (offset == 0)
                offset = 1;

        size_max = (broadcast_off + 1) /* the number of addresses in the subnet */
                   - offset /* exclude the addresses before the offset */
                   - 1; /* exclude the last (broadcast) address */

        /* The pool must contain at least one address */
        assert_return(size_max >= 1, -ERANGE);

        if (size != 0)
                assert_return(size <= size_max, -ERANGE);
        else
                size = size_max;

        if (server->address != address->s_addr || server->netmask != netmask || server->pool_size != size || server->pool_offset != offset) {

                server->pool_offset = offset;
                server->pool_size = size;

                server->address = address->s_addr;
                server->netmask = netmask;
                server->subnet = address->s_addr & netmask;
        }

        return 0;
}

int sd_dhcp_server_is_running(sd_dhcp_server *server) {
        if (!server)
                return false;

        return !!server->receive_message;
}

int sd_dhcp_server_is_in_relay_mode(sd_dhcp_server *server) {
        assert_return(server, -EINVAL);

        return in4_addr_is_set(&server->relay_target);
}

static sd_dhcp_server *dhcp_server_free(sd_dhcp_server *server) {
        assert(server);

        sd_dhcp_server_stop(server);

        sd_event_unref(server->event);

        free(server->boot_server_name);
        free(server->boot_filename);
        free(server->timezone);
        free(server->domain_name);

        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(server->servers[i].addr);

        server->bound_leases_by_address = hashmap_free(server->bound_leases_by_address);
        server->bound_leases_by_client_id = hashmap_free(server->bound_leases_by_client_id);
        server->static_leases_by_address = hashmap_free(server->static_leases_by_address);
        server->static_leases_by_client_id = hashmap_free(server->static_leases_by_client_id);

        hashmap_free(server->extra_options);
        hashmap_free(server->vendor_options);

        free(server->agent_circuit_id);
        free(server->agent_remote_id);

        safe_close(server->lease_dir_fd);
        free(server->lease_file);

        free(server->ifname);
        return mfree(server);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_server, sd_dhcp_server, dhcp_server_free);

int sd_dhcp_server_new(sd_dhcp_server **ret, int ifindex) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;

        assert_return(ret, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        server = new(sd_dhcp_server, 1);
        if (!server)
                return -ENOMEM;

        *server = (sd_dhcp_server) {
                .n_ref = 1,
                .fd_raw = -EBADF,
                .fd = -EBADF,
                .fd_broadcast = -EBADF,
                .address = htobe32(INADDR_ANY),
                .netmask = htobe32(INADDR_ANY),
                .ifindex = ifindex,
                .bind_to_interface = true,
                .default_lease_time = DHCP_DEFAULT_LEASE_TIME_USEC,
                .max_lease_time = DHCP_MAX_LEASE_TIME_USEC,
                .rapid_commit = true,
                .lease_dir_fd = -EBADF,
        };

        *ret = TAKE_PTR(server);

        return 0;
}

int sd_dhcp_server_set_ifname(sd_dhcp_server *server, const char *ifname) {
        assert_return(server, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&server->ifname, ifname);
}

int sd_dhcp_server_get_ifname(sd_dhcp_server *server, const char **ret) {
        int r;

        assert_return(server, -EINVAL);

        r = get_ifname(server->ifindex, &server->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = server->ifname;

        return 0;
}

int sd_dhcp_server_attach_event(sd_dhcp_server *server, sd_event *event, int64_t priority) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!server->event, -EBUSY);

        if (event)
                server->event = sd_event_ref(event);
        else {
                r = sd_event_default(&server->event);
                if (r < 0)
                        return r;
        }

        server->event_priority = priority;

        return 0;
}

int sd_dhcp_server_detach_event(sd_dhcp_server *server) {
        assert_return(server, -EINVAL);

        server->event = sd_event_unref(server->event);

        return 0;
}

sd_event *sd_dhcp_server_get_event(sd_dhcp_server *server) {
        assert_return(server, NULL);

        return server->event;
}

int sd_dhcp_server_set_boot_server_address(sd_dhcp_server *server, const struct in_addr *address) {
        assert_return(server, -EINVAL);

        if (address)
                server->boot_server_address = *address;
        else
                server->boot_server_address = (struct in_addr) {};

        return 0;
}

int sd_dhcp_server_set_boot_server_name(sd_dhcp_server *server, const char *name) {
        int r;

        assert_return(server, -EINVAL);

        if (name) {
                r = dns_name_is_valid(name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        return free_and_strdup(&server->boot_server_name, name);
}

int sd_dhcp_server_set_boot_filename(sd_dhcp_server *server, const char *filename) {
        assert_return(server, -EINVAL);

        if (filename && !string_is_safe_ascii(filename))
                return -EINVAL;

        return free_and_strdup(&server->boot_filename, filename);
}

int sd_dhcp_server_stop(sd_dhcp_server *server) {
        bool running;

        if (!server)
                return 0;

        running = sd_dhcp_server_is_running(server);

        server->receive_message = sd_event_source_disable_unref(server->receive_message);
        server->receive_broadcast = sd_event_source_disable_unref(server->receive_broadcast);

        server->fd_raw = safe_close(server->fd_raw);
        server->fd = safe_close(server->fd);
        server->fd_broadcast = safe_close(server->fd_broadcast);

        if (running)
                log_dhcp_server(server, "STOPPED");

        return 0;
}

bool address_is_in_pool(sd_dhcp_server *server, be32_t address) {
        assert(server);

        if (server->pool_size == 0)
                return false;

        if (address == server->address)
                return false;

        if (be32toh(address) < (be32toh(server->subnet) | server->pool_offset) ||
            be32toh(address) >= (be32toh(server->subnet) | (server->pool_offset + server->pool_size)))
                return false;

        if (hashmap_contains(server->static_leases_by_address, UINT32_TO_PTR(address)))
                return false;

        return true;
}

bool address_available(sd_dhcp_server *server, be32_t address) {
        assert(server);

        if (hashmap_contains(server->bound_leases_by_address, UINT32_TO_PTR(address)) ||
            hashmap_contains(server->static_leases_by_address, UINT32_TO_PTR(address)) ||
            address == server->address)
                return false;

        return true;
}

static void dhcp_server_update_lease_servers(sd_dhcp_server *server) {
        assert(server);
        assert(server->address != 0);

        /* Convert null address -> server address */

        for (sd_dhcp_lease_server_type_t k = 0; k < _SD_DHCP_LEASE_SERVER_TYPE_MAX; k++)
                for (size_t i = 0; i < server->servers[k].size; i++)
                        if (in4_addr_is_null(&server->servers[k].addr[i]))
                                server->servers[k].addr[i].s_addr = server->address;
}

int sd_dhcp_server_start(sd_dhcp_server *server) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(server->event, -EINVAL);

        if (sd_dhcp_server_is_running(server))
                return 0;

        assert_return(!server->receive_message, -EBUSY);
        assert_return(server->fd_raw < 0, -EBUSY);
        assert_return(server->fd < 0, -EBUSY);
        assert_return(server->address != htobe32(INADDR_ANY), -EUNATCH);

        dhcp_server_update_lease_servers(server);

        r = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (r < 0) {
                r = -errno;
                goto on_error;
        }
        server->fd_raw = r;

        if (server->bind_to_interface)
                r = dhcp_network_bind_udp_socket(server->ifindex, INADDR_ANY, DHCP_PORT_SERVER, -1);
        else
                r = dhcp_network_bind_udp_socket(0, server->address, DHCP_PORT_SERVER, -1);
        if (r < 0)
                goto on_error;
        server->fd = r;

        r = sd_event_add_io(server->event, &server->receive_message,
                            server->fd, EPOLLIN,
                            dhcp_server_receive_message, server);
        if (r < 0)
                goto on_error;

        r = sd_event_source_set_priority(server->receive_message,
                                         server->event_priority);
        if (r < 0)
                goto on_error;

        if (!server->bind_to_interface) {
                r = dhcp_network_bind_udp_socket(server->ifindex, INADDR_BROADCAST, DHCP_PORT_SERVER, -1);
                if (r < 0)
                        goto on_error;

                server->fd_broadcast = r;

                r = sd_event_add_io(server->event, &server->receive_broadcast,
                                    server->fd_broadcast, EPOLLIN,
                                    dhcp_server_receive_message, server);
                if (r < 0)
                        goto on_error;

                r = sd_event_source_set_priority(server->receive_broadcast,
                                                 server->event_priority);
                if (r < 0)
                        goto on_error;
        }

        r = dhcp_server_load_leases(server);
        if (r < 0)
                log_dhcp_server_errno(server, r, "Failed to load lease file %s, ignoring: %m", strna(server->lease_file));

        log_dhcp_server(server, "STARTED");

        return 0;

on_error:
        sd_dhcp_server_stop(server);
        return r;
}

int sd_dhcp_server_set_bind_to_interface(sd_dhcp_server *server, int enabled) {
        assert_return(server, -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        if (!!enabled == server->bind_to_interface)
                return 0;

        server->bind_to_interface = enabled;

        return 1;
}

int sd_dhcp_server_set_timezone(sd_dhcp_server *server, const char *tz) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(timezone_is_valid(tz, LOG_DEBUG), -EINVAL);

        if (streq_ptr(tz, server->timezone))
                return 0;

        r = free_and_strdup(&server->timezone, tz);
        if (r < 0)
                return r;

        return 1;
}

int sd_dhcp_server_set_domain_name(sd_dhcp_server *server, const char *domain_name) {
        int r;

        assert_return(server, -EINVAL);

        if (domain_name) {
                r = dns_name_is_valid(domain_name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        return free_and_strdup(&server->domain_name, domain_name);
}

int sd_dhcp_server_set_max_lease_time(sd_dhcp_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        server->max_lease_time = t;
        return 0;
}

int sd_dhcp_server_set_default_lease_time(sd_dhcp_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        server->default_lease_time = t;
        return 0;
}

int sd_dhcp_server_set_ipv6_only_preferred_usec(sd_dhcp_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        /* When 0 is set, disables the IPv6 only mode. */

        /* Refuse too short timespan unless test mode is enabled. */
        if (t > 0 && t < MIN_V6ONLY_WAIT_USEC && !network_test_mode_enabled())
                 return -EINVAL;

        server->ipv6_only_preferred_usec = t;
        return 0;
}

int sd_dhcp_server_set_rapid_commit(sd_dhcp_server *server, int enabled) {
        assert_return(server, -EINVAL);

        server->rapid_commit = enabled;
        return 0;
}

int sd_dhcp_server_set_servers(
                sd_dhcp_server *server,
                sd_dhcp_lease_server_type_t what,
                const struct in_addr addresses[],
                size_t n_addresses) {

        struct in_addr *c = NULL;

        assert_return(server, -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);
        assert_return(addresses || n_addresses == 0, -EINVAL);
        assert_return(what >= 0, -EINVAL);
        assert_return(what < _SD_DHCP_LEASE_SERVER_TYPE_MAX, -EINVAL);

        if (server->servers[what].size == n_addresses &&
            memcmp(server->servers[what].addr, addresses, sizeof(struct in_addr) * n_addresses) == 0)
                return 0;

        if (n_addresses > 0) {
                c = newdup(struct in_addr, addresses, n_addresses);
                if (!c)
                        return -ENOMEM;
        }

        free_and_replace(server->servers[what].addr, c);
        server->servers[what].size = n_addresses;
        return 1;
}

int sd_dhcp_server_set_dns(sd_dhcp_server *server, const struct in_addr dns[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_DNS, dns, n);
}
int sd_dhcp_server_set_ntp(sd_dhcp_server *server, const struct in_addr ntp[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_NTP, ntp, n);
}
int sd_dhcp_server_set_sip(sd_dhcp_server *server, const struct in_addr sip[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_SIP, sip, n);
}
int sd_dhcp_server_set_pop3(sd_dhcp_server *server, const struct in_addr pop3[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_POP3, pop3, n);
}
int sd_dhcp_server_set_smtp(sd_dhcp_server *server, const struct in_addr smtp[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_SMTP, smtp, n);
}
int sd_dhcp_server_set_lpr(sd_dhcp_server *server, const struct in_addr lpr[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_LPR, lpr, n);
}

int sd_dhcp_server_set_router(sd_dhcp_server *server, const struct in_addr *router) {
        assert_return(server, -EINVAL);

        /* router is NULL: router option will not be appended.
         * router is null address (0.0.0.0): the server address will be used as the router address.
         * otherwise: the specified address will be used as the router address. */

        server->emit_router = router;
        if (router)
                server->router_address = *router;

        return 0;
}

static int dhcp_server_set_options(sd_dhcp_server *server, Hashmap *options, Hashmap **dest) {
        int r;

        assert(server);
        assert(dest);

        _cleanup_hashmap_free_ Hashmap *copy = NULL;
        r = dhcp_options_append_many(&copy, options);
        if (r < 0)
                return r;

        return hashmap_free_and_replace(*dest, copy);
}

int dhcp_server_set_extra_options(sd_dhcp_server *server, Hashmap *options) {
        assert(server);
        return dhcp_server_set_options(server, options, &server->extra_options);
}

int dhcp_server_set_vendor_options(sd_dhcp_server *server, Hashmap *options) {
        assert(server);
        return dhcp_server_set_options(server, options, &server->vendor_options);
}

int sd_dhcp_server_set_callback(sd_dhcp_server *server, sd_dhcp_server_callback_t cb, void *userdata) {
        assert_return(server, -EINVAL);

        server->callback = cb;
        server->callback_userdata = userdata;

        return 0;
}

int sd_dhcp_server_set_relay_target(sd_dhcp_server *server, const struct in_addr *address) {
        assert_return(server, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        if (memcmp(address, &server->relay_target, sizeof(struct in_addr)) == 0)
                return 0;

        server->relay_target = *address;
        return 1;
}

int sd_dhcp_server_set_relay_agent_information(
                sd_dhcp_server *server,
                const char *agent_circuit_id,
                const char *agent_remote_id) {

        _cleanup_free_ char *circuit_id_dup = NULL, *remote_id_dup = NULL;

        assert_return(server, -EINVAL);

        if (agent_circuit_id) {
                circuit_id_dup = strdup(agent_circuit_id);
                if (!circuit_id_dup)
                        return -ENOMEM;
        }

        if (agent_remote_id) {
                remote_id_dup = strdup(agent_remote_id);
                if (!remote_id_dup)
                        return -ENOMEM;
        }

        free_and_replace(server->agent_circuit_id, circuit_id_dup);
        free_and_replace(server->agent_remote_id, remote_id_dup);
        return 0;
}

int sd_dhcp_server_set_lease_file(sd_dhcp_server *server, int dir_fd, const char *path) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!path || (dir_fd >= 0 || dir_fd == AT_FDCWD), -EBADF);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        if (!path) {
                /* When NULL, clear the previous assignment. */
                server->lease_file = mfree(server->lease_file);
                server->lease_dir_fd = safe_close(server->lease_dir_fd);
                return 0;
        }

        if (!path_is_safe(path))
                return -EINVAL;

        _cleanup_close_ int fd = AT_FDCWD; /* Unlike our usual coding style, AT_FDCWD needs to be set,
                                            * to pass a 'valid' fd. */
        if (dir_fd >= 0) {
                fd = fd_reopen(dir_fd, O_CLOEXEC | O_DIRECTORY | O_PATH);
                if (fd < 0)
                        return fd;
        }

        r = free_and_strdup(&server->lease_file, path);
        if (r < 0)
                return r;

        close_and_replace(server->lease_dir_fd, fd);

        return 0;
}

static int find_lease_address(Hashmap *h, const char *name, struct in_addr *ret) {
        int r;

        assert(name);

        sd_dhcp_server_lease *lease;
        HASHMAP_FOREACH(lease, h) {
                if (!lease->hostname)
                        continue;

                r = dns_name_equal(lease->hostname, name);
                if (r <= 0)
                        continue;

                if (ret)
                        ret->s_addr = lease->address;
                return 1;
        }

        return -ENOENT;
}

int sd_dhcp_server_get_lease_address_by_name(sd_dhcp_server *server, const char *name, struct in_addr *ret) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(dns_name_is_valid(name), -EINVAL);

        r = find_lease_address(server->static_leases_by_address, name, ret);
        if (r != -ENOENT)
                return r;

        return find_lease_address(server->bound_leases_by_address, name, ret);
}
