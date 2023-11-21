/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcpclienthfoo
#define foosddhcpclienthfoo

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
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdbool.h>

#include "sd-device.h"
#include "sd-dhcp-client-id.h"
#include "sd-dhcp-lease.h"
#include "sd-dhcp-option.h"
#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_DHCP_CLIENT_EVENT_STOP               = 0,
        SD_DHCP_CLIENT_EVENT_IP_ACQUIRE         = 1,
        SD_DHCP_CLIENT_EVENT_IP_CHANGE          = 2,
        SD_DHCP_CLIENT_EVENT_EXPIRED            = 3,
        SD_DHCP_CLIENT_EVENT_RENEW              = 4,
        SD_DHCP_CLIENT_EVENT_SELECTING          = 5,
        SD_DHCP_CLIENT_EVENT_TRANSIENT_FAILURE  = 6 /* Sent when we have not received a reply after the first few attempts.
                                                     * The client may want to start acquiring link-local addresses. */
};

typedef struct sd_dhcp_client sd_dhcp_client;

typedef int (*sd_dhcp_client_callback_t)(sd_dhcp_client *client, int event, void *userdata);
int sd_dhcp_client_set_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata);

int sd_dhcp_client_set_request_option(
                sd_dhcp_client *client,
                uint8_t option);
int sd_dhcp_client_set_request_address(
                sd_dhcp_client *client,
                const struct in_addr *last_address);
int sd_dhcp_client_set_request_broadcast(
                sd_dhcp_client *client,
                int broadcast);
int sd_dhcp_client_set_ifindex(
                sd_dhcp_client *client,
                int interface_index);
int sd_dhcp_client_set_ifname(
                sd_dhcp_client *client,
                const char *interface_name);
int sd_dhcp_client_get_ifname(sd_dhcp_client *client, const char **ret);
int sd_dhcp_client_set_mac(
                sd_dhcp_client *client,
                const uint8_t *hw_addr,
                const uint8_t *bcast_addr,
                size_t addr_len,
                uint16_t arp_type);
int sd_dhcp_client_get_client_id(
                sd_dhcp_client *client,
                const sd_dhcp_client_id **ret);
int sd_dhcp_client_set_client_id(
                sd_dhcp_client *client,
                uint8_t type,
                const uint8_t *data,
                size_t data_len);
__extension__ int sd_dhcp_client_set_iaid_duid_llt(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                uint64_t llt_time);
__extension__ int sd_dhcp_client_set_iaid_duid_ll(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid);
__extension__ int sd_dhcp_client_set_iaid_duid_en(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid);
__extension__ int sd_dhcp_client_set_iaid_duid_uuid(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid);
__extension__ int sd_dhcp_client_set_iaid_duid_raw(
                sd_dhcp_client *client,
                bool iaid_set,
                uint32_t iaid,
                uint16_t duid_type,
                const uint8_t *duid,
                size_t duid_len);
__extension__ int sd_dhcp_client_set_rapid_commit(
                sd_dhcp_client *client,
                bool rapid_commit);
__extension__ int sd_dhcp_client_set_keep_alive(
                sd_dhcp_client *client,
                bool keep_alive);
int sd_dhcp_client_set_mtu(
                sd_dhcp_client *client,
                uint32_t mtu);
int sd_dhcp_client_set_max_attempts(
                sd_dhcp_client *client,
                uint64_t attempt);
int sd_dhcp_client_set_client_port(
                sd_dhcp_client *client,
                uint16_t port);
int sd_dhcp_client_set_hostname(
                sd_dhcp_client *client,
                const char *hostname);
int sd_dhcp_client_set_vendor_class_identifier(
                sd_dhcp_client *client,
                const char *vci);
int sd_dhcp_client_set_mud_url(
                sd_dhcp_client *client,
                const char *mudurl);
int sd_dhcp_client_set_user_class(
                sd_dhcp_client *client,
                char * const *user_class);
int sd_dhcp_client_get_lease(
                sd_dhcp_client *client,
                sd_dhcp_lease **ret);
int sd_dhcp_client_set_service_type(
                sd_dhcp_client *client,
                int type);
int sd_dhcp_client_set_socket_priority(
                sd_dhcp_client *client,
                int so_priority);
int sd_dhcp_client_set_fallback_lease_lifetime(
                sd_dhcp_client *client,
                uint64_t fallback_lease_lifetime);

int sd_dhcp_client_add_option(sd_dhcp_client *client, sd_dhcp_option *v);
int sd_dhcp_client_add_vendor_option(sd_dhcp_client *client, sd_dhcp_option *v);

int sd_dhcp_client_is_running(sd_dhcp_client *client);
int sd_dhcp_client_stop(sd_dhcp_client *client);
int sd_dhcp_client_start(sd_dhcp_client *client);
int sd_dhcp_client_send_release(sd_dhcp_client *client);
int sd_dhcp_client_send_decline(sd_dhcp_client *client);
int sd_dhcp_client_send_renew(sd_dhcp_client *client);
int sd_dhcp_client_set_ipv6_connectivity(sd_dhcp_client *client, int have);
int sd_dhcp_client_interrupt_ipv6_only_mode(sd_dhcp_client *client);

sd_dhcp_client *sd_dhcp_client_ref(sd_dhcp_client *client);
sd_dhcp_client *sd_dhcp_client_unref(sd_dhcp_client *client);

/* NOTE: anonymize parameter is used to initialize PRL memory with different
 * options when using RFC7844 Anonymity Profiles */
int sd_dhcp_client_new(sd_dhcp_client **ret, int anonymize);

int sd_dhcp_client_attach_event(
                sd_dhcp_client *client,
                sd_event *event,
                int64_t priority);
int sd_dhcp_client_detach_event(sd_dhcp_client *client);
sd_event *sd_dhcp_client_get_event(sd_dhcp_client *client);
int sd_dhcp_client_attach_device(sd_dhcp_client *client, sd_device *dev);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp_client, sd_dhcp_client_unref);

_SD_END_DECLARATIONS;

#endif
