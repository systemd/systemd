/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpserverhfoo
#define foosddhcpserverhfoo

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <netinet/in.h>

#include "sd-dhcp-lease.h"
#include "sd-dhcp-option.h"
#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp_server sd_dhcp_server;

enum {
        SD_DHCP_SERVER_EVENT_LEASE_CHANGED                      = 1 << 0
};

int sd_dhcp_server_new(sd_dhcp_server **ret, int ifindex);

int sd_dhcp_server_set_ifname(sd_dhcp_server *server, const char *ifname);
int sd_dhcp_server_get_ifname(sd_dhcp_server *server, const char **ret);

sd_dhcp_server *sd_dhcp_server_ref(sd_dhcp_server *server);
sd_dhcp_server *sd_dhcp_server_unref(sd_dhcp_server *server);

int sd_dhcp_server_attach_event(sd_dhcp_server *server, sd_event *event, int64_t priority);
int sd_dhcp_server_detach_event(sd_dhcp_server *server);
sd_event *sd_dhcp_server_get_event(sd_dhcp_server *server);

typedef void (*sd_dhcp_server_callback_t)(sd_dhcp_server *server, uint64_t event, void *userdata);

int sd_dhcp_server_set_callback(sd_dhcp_server *server, sd_dhcp_server_callback_t cb, void *userdata);

int sd_dhcp_server_is_running(sd_dhcp_server *server);

int sd_dhcp_server_start(sd_dhcp_server *server);
int sd_dhcp_server_stop(sd_dhcp_server *server);

int sd_dhcp_server_configure_pool(sd_dhcp_server *server, const struct in_addr *address, unsigned char prefixlen, uint32_t offset, uint32_t size);

int sd_dhcp_server_set_boot_server_address(sd_dhcp_server *server, const struct in_addr *address);
int sd_dhcp_server_set_boot_server_name(sd_dhcp_server *server, const char *name);
int sd_dhcp_server_set_boot_filename(sd_dhcp_server *server, const char *filename);
int sd_dhcp_server_set_bind_to_interface(sd_dhcp_server *server, int enabled);
int sd_dhcp_server_set_timezone(sd_dhcp_server *server, const char *timezone);
int sd_dhcp_server_set_router(sd_dhcp_server *server, const struct in_addr *address);

int sd_dhcp_server_set_servers(
                sd_dhcp_server *server,
                sd_dhcp_lease_server_type_t what,
                const struct in_addr addresses[],
                size_t n_addresses);

int sd_dhcp_server_set_lpr(sd_dhcp_server *server, const struct in_addr lpr[], size_t n);
int sd_dhcp_server_set_dns(sd_dhcp_server *server, const struct in_addr dns[], size_t n);
int sd_dhcp_server_set_ntp(sd_dhcp_server *server, const struct in_addr ntp[], size_t n);
int sd_dhcp_server_set_sip(sd_dhcp_server *server, const struct in_addr sip[], size_t n);
int sd_dhcp_server_set_pop3(sd_dhcp_server *server, const struct in_addr pop3[], size_t n);
int sd_dhcp_server_set_smtp(sd_dhcp_server *server, const struct in_addr smtp[], size_t n);

int sd_dhcp_server_add_option(sd_dhcp_server *server, sd_dhcp_option *v);
int sd_dhcp_server_add_vendor_option(sd_dhcp_server *server, sd_dhcp_option *v);
int sd_dhcp_server_set_static_lease(sd_dhcp_server *server, const struct in_addr *address, uint8_t *client_id, size_t client_id_size);
int sd_dhcp_server_set_lease_file(sd_dhcp_server *server, const char *path);

int sd_dhcp_server_set_max_lease_time(sd_dhcp_server *server, uint64_t t);
int sd_dhcp_server_set_default_lease_time(sd_dhcp_server *server, uint64_t t);
int sd_dhcp_server_set_ipv6_only_preferred_usec(sd_dhcp_server *server, uint64_t t);
int sd_dhcp_server_set_rapid_commit(sd_dhcp_server *server, int enabled);

int sd_dhcp_server_forcerenew(sd_dhcp_server *server);

int sd_dhcp_server_is_in_relay_mode(sd_dhcp_server *server);
int sd_dhcp_server_set_relay_target(sd_dhcp_server *server, const struct in_addr* address);
int sd_dhcp_server_set_relay_agent_information(sd_dhcp_server *server, const char* circuit_id, const char* remote_id);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_server, sd_dhcp_server_unref);

_SD_END_DECLARATIONS;

#endif
