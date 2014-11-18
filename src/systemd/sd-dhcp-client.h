/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosddhcpclienthfoo
#define foosddhcpclienthfoo

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

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

#include <netinet/in.h>
#include <net/ethernet.h>

#include "sd-event.h"
#include "sd-dhcp-lease.h"

enum {
        DHCP_EVENT_STOP                         = 0,
        DHCP_EVENT_IP_ACQUIRE                   = 1,
        DHCP_EVENT_IP_CHANGE                    = 2,
        DHCP_EVENT_EXPIRED                      = 3,
        DHCP_EVENT_RENEW                        = 4,
};

typedef struct sd_dhcp_client sd_dhcp_client;

typedef void (*sd_dhcp_client_cb_t)(sd_dhcp_client *client, int event,
                                    void *userdata);
int sd_dhcp_client_set_callback(sd_dhcp_client *client, sd_dhcp_client_cb_t cb,
                                void *userdata);


int sd_dhcp_client_set_request_option(sd_dhcp_client *client, uint8_t option);
int sd_dhcp_client_set_request_address(sd_dhcp_client *client,
                                       const struct in_addr *last_address);
int sd_dhcp_client_set_request_broadcast(sd_dhcp_client *client, int broadcast);
int sd_dhcp_client_set_index(sd_dhcp_client *client, int interface_index);
int sd_dhcp_client_set_mac(sd_dhcp_client *client, const uint8_t *addr,
                           size_t addr_len, uint16_t arp_type);
int sd_dhcp_client_set_client_id(sd_dhcp_client *client, uint8_t type,
                                 const uint8_t *data, size_t data_len);
int sd_dhcp_client_get_client_id(sd_dhcp_client *client, uint8_t *type,
                                 const uint8_t **data, size_t *data_len);
int sd_dhcp_client_set_mtu(sd_dhcp_client *client, uint32_t mtu);
int sd_dhcp_client_set_hostname(sd_dhcp_client *client, const char *hostname);
int sd_dhcp_client_set_vendor_class_identifier(sd_dhcp_client *client, const char *vci);
int sd_dhcp_client_get_lease(sd_dhcp_client *client, sd_dhcp_lease **ret);

int sd_dhcp_client_stop(sd_dhcp_client *client);
int sd_dhcp_client_start(sd_dhcp_client *client);

sd_dhcp_client *sd_dhcp_client_ref(sd_dhcp_client *client);
sd_dhcp_client *sd_dhcp_client_unref(sd_dhcp_client *client);

int sd_dhcp_client_new(sd_dhcp_client **ret);

int sd_dhcp_client_attach_event(sd_dhcp_client *client, sd_event *event, int priority);
int sd_dhcp_client_detach_event(sd_dhcp_client *client);
sd_event *sd_dhcp_client_get_event(sd_dhcp_client *client);

#endif
