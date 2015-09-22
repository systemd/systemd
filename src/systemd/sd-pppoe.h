/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdpppoefoo
#define foosdpppoefoo

/***
  This file is part of systemd.

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

#include <stdbool.h>
#include <net/ethernet.h>

#include "sd-event.h"

#include "sparse-endian.h"

enum {
        SD_PPPOE_EVENT_RUNNING          = 0,
        SD_PPPOE_EVENT_STOPPED          = 1,
};

typedef struct sd_pppoe sd_pppoe;
typedef void (*sd_pppoe_cb_t)(sd_pppoe *ppp, int event, void *userdata);

int sd_pppoe_detach_event(sd_pppoe *ppp);
int sd_pppoe_attach_event(sd_pppoe *ppp, sd_event *event, int priority);
int sd_pppoe_get_channel(sd_pppoe *ppp, int *channel);
int sd_pppoe_set_callback(sd_pppoe *ppp, sd_pppoe_cb_t cb, void *userdata);
int sd_pppoe_set_ifindex(sd_pppoe *ppp, int ifindex);
int sd_pppoe_set_ifname(sd_pppoe *ppp, const char *ifname);
int sd_pppoe_set_service_name(sd_pppoe *ppp, const char *service_name);
int sd_pppoe_start(sd_pppoe *ppp);
int sd_pppoe_stop(sd_pppoe *ppp);
sd_pppoe *sd_pppoe_ref(sd_pppoe *ppp);
sd_pppoe *sd_pppoe_unref(sd_pppoe *ppp);
int sd_pppoe_new (sd_pppoe **ret);

#endif
