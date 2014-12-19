/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

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

#pragma once

#include "sd-event.h"

typedef struct sd_lldp sd_lldp;

typedef void (*sd_lldp_cb_t)(sd_lldp *lldp, int event, void *userdata);

enum {
        UPDATE_INFO = 10,
};

typedef enum LLDPPortStatus {
        LLDP_PORT_STATUS_NONE,
        LLDP_PORT_STATUS_ENABLED,
        LLDP_PORT_STATUS_DISABLED,
        _LLDP_PORT_STATUS_MAX,
        _LLDP_PORT_STATUS_INVALID = -1,
} LLDPPortStatus;

int sd_lldp_new(int ifindex, const char *ifname, const struct ether_addr *mac, sd_lldp **ret);
void sd_lldp_free(sd_lldp *lldp);

int sd_lldp_start(sd_lldp *lldp);
int sd_lldp_stop(sd_lldp *lldp);

int sd_lldp_attach_event(sd_lldp *lldp, sd_event *event, int priority);
int sd_lldp_detach_event(sd_lldp *lldp);

int sd_lldp_set_callback(sd_lldp *lldp, sd_lldp_cb_t cb, void *userdata);
int sd_lldp_save(sd_lldp *lldp, const char *file);
