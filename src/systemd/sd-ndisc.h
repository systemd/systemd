/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscfoo
#define foosdndiscfoo

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

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "sd-event.h"
#include "sd-ndisc-neighbor.h"
#include "sd-ndisc-protocol.h"
#include "sd-ndisc-redirect.h"
#include "sd-ndisc-router.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_ndisc sd_ndisc;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_ndisc_event_t) {
        SD_NDISC_EVENT_TIMEOUT,
        SD_NDISC_EVENT_ROUTER,
        SD_NDISC_EVENT_NEIGHBOR,
        SD_NDISC_EVENT_REDIRECT,
        _SD_NDISC_EVENT_MAX,
        _SD_NDISC_EVENT_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(NDISC_EVENT)
} sd_ndisc_event_t;

typedef void (*sd_ndisc_callback_t)(sd_ndisc *nd, sd_ndisc_event_t event, void *message, void *userdata);

int sd_ndisc_new(sd_ndisc **ret);
sd_ndisc *sd_ndisc_ref(sd_ndisc *nd);
sd_ndisc *sd_ndisc_unref(sd_ndisc *nd);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_ndisc, sd_ndisc_unref);

int sd_ndisc_start(sd_ndisc *nd);
int sd_ndisc_stop(sd_ndisc *nd);
int sd_ndisc_is_running(sd_ndisc *nd);

int sd_ndisc_attach_event(sd_ndisc *nd, sd_event *event, int64_t priority);
int sd_ndisc_detach_event(sd_ndisc *nd);
sd_event *sd_ndisc_get_event(sd_ndisc *nd);

int sd_ndisc_set_callback(sd_ndisc *nd, sd_ndisc_callback_t cb, void *userdata);
int sd_ndisc_set_ifindex(sd_ndisc *nd, int interface_index);
int sd_ndisc_set_ifname(sd_ndisc *nd, const char *interface_name);
int sd_ndisc_get_ifname(sd_ndisc *nd, const char **ret);
int sd_ndisc_set_link_local_address(sd_ndisc *nd, const struct in6_addr *addr);
int sd_ndisc_set_mac(sd_ndisc *nd, const struct ether_addr *mac_addr);

_SD_END_DECLARATIONS;

#endif
