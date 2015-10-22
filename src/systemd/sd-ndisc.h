/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdndiscfoo
#define foosdndiscfoo

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

#include <inttypes.h>
#include <net/ethernet.h>

#include "sd-event.h"
#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_NDISC_EVENT_ROUTER_ADVERTISMENT_NONE         = 0,
        SD_NDISC_EVENT_ROUTER_ADVERTISMENT_TIMEOUT      = 1,
        SD_NDISC_EVENT_ROUTER_ADVERTISMENT_OTHER        = 2,
        SD_NDISC_EVENT_ROUTER_ADVERTISMENT_MANAGED      = 3,
        SD_NDISC_EVENT_STOP                             = 4,
};

typedef struct sd_ndisc sd_ndisc;

typedef void(*sd_ndisc_callback_t)(sd_ndisc *nd, int event,
                                      void *userdata);

int sd_ndisc_set_callback(sd_ndisc *nd, sd_ndisc_callback_t cb,
                             void *userdata);
int sd_ndisc_set_index(sd_ndisc *nd, int interface_index);
int sd_ndisc_set_mac(sd_ndisc *nd, const struct ether_addr *mac_addr);

int sd_ndisc_attach_event(sd_ndisc *nd, sd_event *event, int priority);
int sd_ndisc_detach_event(sd_ndisc *nd);
sd_event *sd_ndisc_get_event(sd_ndisc *nd);

sd_ndisc *sd_ndisc_ref(sd_ndisc *nd);
sd_ndisc *sd_ndisc_unref(sd_ndisc *nd);
int sd_ndisc_new(sd_ndisc **ret);

int sd_ndisc_get_mtu(sd_ndisc *nd, uint32_t *mtu);

int sd_ndisc_stop(sd_ndisc *nd);
int sd_ndisc_router_discovery_start(sd_ndisc *nd);

#define SD_NDISC_ADDRESS_FORMAT_STR "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

#define SD_NDISC_ADDRESS_FORMAT_VAL(address) \
        be16toh((address).s6_addr16[0]),        \
        be16toh((address).s6_addr16[1]),        \
        be16toh((address).s6_addr16[2]),        \
        be16toh((address).s6_addr16[3]),        \
        be16toh((address).s6_addr16[4]),        \
        be16toh((address).s6_addr16[5]),        \
        be16toh((address).s6_addr16[6]),        \
        be16toh((address).s6_addr16[7])

_SD_END_DECLARATIONS;

#endif
