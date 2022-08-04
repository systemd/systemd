/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdipv4acdfoo
#define foosdipv4acdfoo

/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
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

#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_IPV4ACD_EVENT_STOP           = 0,
        SD_IPV4ACD_EVENT_BIND           = 1,
        SD_IPV4ACD_EVENT_CONFLICT       = 2
};

typedef struct sd_ipv4acd sd_ipv4acd;
typedef void (*sd_ipv4acd_callback_t)(sd_ipv4acd *acd, int event, void *userdata);
typedef int (*sd_ipv4acd_check_mac_callback_t)(sd_ipv4acd *acd, const struct ether_addr *mac, void *userdata);

int sd_ipv4acd_detach_event(sd_ipv4acd *acd);
int sd_ipv4acd_attach_event(sd_ipv4acd *acd, sd_event *event, int64_t priority);
int sd_ipv4acd_get_address(sd_ipv4acd *acd, struct in_addr *address);
int sd_ipv4acd_set_callback(sd_ipv4acd *acd, sd_ipv4acd_callback_t cb, void *userdata);
int sd_ipv4acd_set_check_mac_callback(sd_ipv4acd *acd, sd_ipv4acd_check_mac_callback_t cb, void *userdata);
int sd_ipv4acd_set_mac(sd_ipv4acd *acd, const struct ether_addr *addr);
int sd_ipv4acd_set_ifindex(sd_ipv4acd *acd, int interface_index);
int sd_ipv4acd_get_ifindex(sd_ipv4acd *acd);
int sd_ipv4acd_set_ifname(sd_ipv4acd *acd, const char *interface_name);
int sd_ipv4acd_get_ifname(sd_ipv4acd *acd, const char **ret);
int sd_ipv4acd_set_address(sd_ipv4acd *acd, const struct in_addr *address);
int sd_ipv4acd_is_running(sd_ipv4acd *acd);
__extension__ int sd_ipv4acd_start(sd_ipv4acd *acd, bool reset_conflicts);
int sd_ipv4acd_stop(sd_ipv4acd *acd);
sd_ipv4acd *sd_ipv4acd_ref(sd_ipv4acd *acd);
sd_ipv4acd *sd_ipv4acd_unref(sd_ipv4acd *acd);
int sd_ipv4acd_new(sd_ipv4acd **ret);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ipv4acd, sd_ipv4acd_unref);

_SD_END_DECLARATIONS;

#endif
