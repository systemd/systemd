/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcprelayhfoo
#define foosddhcprelayhfoo

/***
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

#include <netinet/in.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_event sd_event;
typedef struct sd_dhcp_relay sd_dhcp_relay;
typedef struct sd_dhcp_relay_interface sd_dhcp_relay_interface;

_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_relay);
_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_relay_interface);

int sd_dhcp_relay_new(sd_dhcp_relay **ret);

int sd_dhcp_relay_attach_event(sd_dhcp_relay *relay, sd_event *event, int64_t priority);
int sd_dhcp_relay_detach_event(sd_dhcp_relay *relay);
sd_event *sd_dhcp_relay_get_event(sd_dhcp_relay *relay);

int sd_dhcp_relay_set_server_address(sd_dhcp_relay *relay, const struct in_addr *address);
int sd_dhcp_relay_set_server_port(sd_dhcp_relay *relay, uint16_t port);
int sd_dhcp_relay_set_remote_id(sd_dhcp_relay *relay, const struct iovec *iov);
int sd_dhcp_relay_set_server_identifier_override(sd_dhcp_relay *relay, int b);

int sd_dhcp_relay_add_interface(sd_dhcp_relay *relay, int ifindex, int is_upstream, sd_dhcp_relay_interface **ret);

int sd_dhcp_relay_interface_set_ifname(sd_dhcp_relay_interface *interface, const char *ifname);
int sd_dhcp_relay_interface_get_ifname(sd_dhcp_relay_interface *interface, const char **ret);
int sd_dhcp_relay_interface_set_address(sd_dhcp_relay_interface *interface, const struct in_addr *address);
int sd_dhcp_relay_interface_set_port(sd_dhcp_relay_interface *interface, uint16_t port);
int sd_dhcp_relay_interface_set_ip_service_type(sd_dhcp_relay_interface *interface, uint8_t type);
int sd_dhcp_relay_interface_is_running(sd_dhcp_relay_interface *interface);
int sd_dhcp_relay_interface_start(sd_dhcp_relay_interface *interface);
int sd_dhcp_relay_interface_stop(sd_dhcp_relay_interface *interface);

int sd_dhcp_relay_downstream_set_gateway_address(sd_dhcp_relay_interface *interface, const struct in_addr *address);
int sd_dhcp_relay_downstream_set_circuit_id(sd_dhcp_relay_interface *interface, const struct iovec *iov);
int sd_dhcp_relay_downstream_set_virtual_subnet_selection(sd_dhcp_relay_interface *interface, const struct iovec *iov);

int sd_dhcp_relay_upstream_set_priority(sd_dhcp_relay_interface *interface, int64_t priority);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_relay, sd_dhcp_relay_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_relay_interface, sd_dhcp_relay_interface_unref);

_SD_END_DECLARATIONS;

#endif
