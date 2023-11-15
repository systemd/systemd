/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosddhcp6clienthfoo
#define foosddhcp6clienthfoo

/***
  Copyright © 2014 Intel Corporation. All rights reserved.

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
#include <sys/types.h>

#include "sd-device.h"
#include "sd-dhcp-duid.h"
#include "sd-dhcp6-lease.h"
#include "sd-dhcp6-option.h"
#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_DHCP6_CLIENT_EVENT_STOP                      = 0,
        SD_DHCP6_CLIENT_EVENT_RESEND_EXPIRE             = 10,
        SD_DHCP6_CLIENT_EVENT_RETRANS_MAX               = 11,
        SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE                = 12,
        SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST       = 13
};

typedef struct sd_dhcp6_client sd_dhcp6_client;

typedef void (*sd_dhcp6_client_callback_t)(sd_dhcp6_client *client, int event, void *userdata);
int sd_dhcp6_client_set_callback(
                sd_dhcp6_client *client,
                sd_dhcp6_client_callback_t cb,
                void *userdata);

int sd_dhcp6_client_set_ifindex(
                sd_dhcp6_client *client,
                int interface_index);
int sd_dhcp6_client_set_ifname(
                sd_dhcp6_client *client,
                const char *interface_name);
int sd_dhcp6_client_get_ifname(sd_dhcp6_client *client, const char **ret);
int sd_dhcp6_client_set_local_address(
                sd_dhcp6_client *client,
                const struct in6_addr *local_address);
int sd_dhcp6_client_set_mac(
                sd_dhcp6_client *client,
                const uint8_t *addr,
                size_t addr_len,
                uint16_t arp_type);
int sd_dhcp6_client_set_duid_llt(sd_dhcp6_client *client, uint64_t llt_time);
int sd_dhcp6_client_set_duid_ll(sd_dhcp6_client *client);
int sd_dhcp6_client_set_duid_en(sd_dhcp6_client *client);
int sd_dhcp6_client_set_duid_uuid(sd_dhcp6_client *client);
int sd_dhcp6_client_set_duid_raw(sd_dhcp6_client *client, uint16_t duid_type, const uint8_t *duid, size_t duid_len);
int sd_dhcp6_client_set_duid(sd_dhcp6_client *client, const sd_dhcp_duid *duid);
int sd_dhcp6_client_get_duid(sd_dhcp6_client *client, const sd_dhcp_duid **ret);
int sd_dhcp6_client_get_duid_as_string(sd_dhcp6_client *client, char **ret);
int sd_dhcp6_client_set_iaid(
                sd_dhcp6_client *client,
                uint32_t iaid);
int sd_dhcp6_client_get_iaid(
                sd_dhcp6_client *client,
                uint32_t *iaid);
int sd_dhcp6_client_set_fqdn(
                sd_dhcp6_client *client,
                const char *fqdn);
int sd_dhcp6_client_set_information_request(
                sd_dhcp6_client *client,
                int enabled);
int sd_dhcp6_client_get_information_request(
                sd_dhcp6_client *client,
                int *enabled);
int sd_dhcp6_client_set_request_option(
                sd_dhcp6_client *client,
                uint16_t option);
int sd_dhcp6_client_set_request_mud_url(
                sd_dhcp6_client *client,
                const char *mudurl);
int sd_dhcp6_client_set_request_user_class(
                sd_dhcp6_client *client,
                char * const *user_class);
int sd_dhcp6_client_set_request_vendor_class(
                sd_dhcp6_client *client,
                char * const *vendor_class);
int sd_dhcp6_client_set_prefix_delegation_hint(
                sd_dhcp6_client *client,
                uint8_t prefixlen,
                const struct in6_addr *pd_prefix);
int sd_dhcp6_client_get_prefix_delegation(sd_dhcp6_client *client,
                                          int *delegation);
int sd_dhcp6_client_set_prefix_delegation(sd_dhcp6_client *client,
                                          int delegation);
int sd_dhcp6_client_get_address_request(sd_dhcp6_client *client,
                                        int *request);
int sd_dhcp6_client_set_address_request(sd_dhcp6_client *client,
                                        int request);
int sd_dhcp6_client_add_vendor_option(sd_dhcp6_client *client,
                                      sd_dhcp6_option *v);
int sd_dhcp6_client_set_rapid_commit(sd_dhcp6_client *client, int enable);
int sd_dhcp6_client_set_send_release(sd_dhcp6_client *client, int enable);

int sd_dhcp6_client_get_lease(
                sd_dhcp6_client *client,
                sd_dhcp6_lease **ret);

int sd_dhcp6_client_add_option(sd_dhcp6_client *client, sd_dhcp6_option *v);

int sd_dhcp6_client_stop(sd_dhcp6_client *client);
int sd_dhcp6_client_start(sd_dhcp6_client *client);
int sd_dhcp6_client_is_running(sd_dhcp6_client *client);
int sd_dhcp6_client_attach_event(
                sd_dhcp6_client *client,
                sd_event *event,
                int64_t priority);
int sd_dhcp6_client_detach_event(sd_dhcp6_client *client);
sd_event *sd_dhcp6_client_get_event(sd_dhcp6_client *client);
int sd_dhcp6_client_attach_device(sd_dhcp6_client *client, sd_device *dev);
sd_dhcp6_client *sd_dhcp6_client_ref(sd_dhcp6_client *client);
sd_dhcp6_client *sd_dhcp6_client_unref(sd_dhcp6_client *client);
int sd_dhcp6_client_new(sd_dhcp6_client **ret);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_client, sd_dhcp6_client_unref);

_SD_END_DECLARATIONS;

#endif
