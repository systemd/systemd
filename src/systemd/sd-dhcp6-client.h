/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddhcp6clienthfoo
#define foosddhcp6clienthfoo

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

#include "sd-dhcp6-lease.h"

enum {
        DHCP6_EVENT_STOP                        = 0,
        DHCP6_EVENT_RESEND_EXPIRE               = 10,
        DHCP6_EVENT_RETRANS_MAX                 = 11,
        DHCP6_EVENT_IP_ACQUIRE                  = 12,
        DHCP6_EVENT_INFORMATION_REQUEST         = 13,
};

typedef struct sd_dhcp6_client sd_dhcp6_client;

typedef void (*sd_dhcp6_client_cb_t)(sd_dhcp6_client *client, int event,
                                     void *userdata);
int sd_dhcp6_client_set_callback(sd_dhcp6_client *client,
                                 sd_dhcp6_client_cb_t cb, void *userdata);

int sd_dhcp6_client_set_index(sd_dhcp6_client *client, int interface_index);
int sd_dhcp6_client_set_mac(sd_dhcp6_client *client, const uint8_t *addr,
                            size_t addr_len, uint16_t arp_type);
int sd_dhcp6_client_set_duid(sd_dhcp6_client *client, uint16_t type, uint8_t *duid,
                             size_t duid_len);
int sd_dhcp6_client_set_information_request(sd_dhcp6_client *client,
                                            bool enabled);
int sd_dhcp6_client_get_information_request(sd_dhcp6_client *client,
                                            bool *enabled);
int sd_dhcp6_client_set_request_option(sd_dhcp6_client *client,
                                       uint16_t option);

int sd_dhcp6_client_get_lease(sd_dhcp6_client *client, sd_dhcp6_lease **ret);

int sd_dhcp6_client_stop(sd_dhcp6_client *client);
int sd_dhcp6_client_start(sd_dhcp6_client *client);
int sd_dhcp6_client_attach_event(sd_dhcp6_client *client, sd_event *event,
                                 int priority);
int sd_dhcp6_client_detach_event(sd_dhcp6_client *client);
sd_event *sd_dhcp6_client_get_event(sd_dhcp6_client *client);
sd_dhcp6_client *sd_dhcp6_client_ref(sd_dhcp6_client *client);
sd_dhcp6_client *sd_dhcp6_client_unref(sd_dhcp6_client *client);
int sd_dhcp6_client_new(sd_dhcp6_client **ret);

#endif
