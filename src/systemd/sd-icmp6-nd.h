/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdicmp6ndfoo
#define foosdicmp6ndfoo

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

#include <net/ethernet.h>

#include "sd-event.h"

enum {
        ICMP6_EVENT_ROUTER_ADVERTISMENT_NONE    = 0,
        ICMP6_EVENT_ROUTER_ADVERTISMENT_TIMEOUT = 1,
        ICMP6_EVENT_ROUTER_ADVERTISMENT_OTHER   = 2,
        ICMP6_EVENT_ROUTER_ADVERTISMENT_MANAGED = 3,
};

typedef struct sd_icmp6_nd sd_icmp6_nd;

typedef void(*sd_icmp6_nd_callback_t)(sd_icmp6_nd *nd, int event,
                                      void *userdata);

int sd_icmp6_nd_set_callback(sd_icmp6_nd *nd, sd_icmp6_nd_callback_t cb,
                             void *userdata);
int sd_icmp6_nd_set_index(sd_icmp6_nd *nd, int interface_index);
int sd_icmp6_nd_set_mac(sd_icmp6_nd *nd, const struct ether_addr *mac_addr);

int sd_icmp6_nd_attach_event(sd_icmp6_nd *nd, sd_event *event, int priority);
int sd_icmp6_nd_detach_event(sd_icmp6_nd *nd);
sd_event *sd_icmp6_nd_get_event(sd_icmp6_nd *nd);

sd_icmp6_nd *sd_icmp6_nd_ref(sd_icmp6_nd *nd);
sd_icmp6_nd *sd_icmp6_nd_unref(sd_icmp6_nd *nd);
int sd_icmp6_nd_new(sd_icmp6_nd **ret);

int sd_icmp6_nd_stop(sd_icmp6_nd *nd);
int sd_icmp6_router_solicitation_start(sd_icmp6_nd *nd);

#endif
