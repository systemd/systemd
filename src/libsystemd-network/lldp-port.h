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

#include <net/ethernet.h>

#include "sd-event.h"
#include "sd-lldp.h"

typedef struct lldp_port lldp_port;

struct lldp_port {
        LLDPPortStatus status;

        int ifindex;
        char *ifname;

        struct ether_addr mac;

        int rawfd;

        sd_event *event;
        sd_event_source *lldp_port_rx;

        int event_priority;

        void *userdata;
};

int lldp_port_new(int ifindex,
                  char *ifname,
                  const struct ether_addr *addr,
                  void *userdata,
                  lldp_port **ret);
void lldp_port_free(lldp_port *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(lldp_port*, lldp_port_free);
#define _cleanup_lldp_port_free_ _cleanup_(lldp_port_freep)

int lldp_port_start(lldp_port *p);
int lldp_port_stop(lldp_port *p);
