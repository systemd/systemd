/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <string.h>

#include "udev.h"
#include "udev-util.h"
#include "virt.h"
#include "siphash24.h"
#include "util.h"
#include "refcnt.h"

#include "network-internal.h"
#include "sd-dhcp6-client.h"
#include "dhcp6-protocol.h"
#include "dhcp6-internal.h"

#define SYSTEMD_PEN 43793
#define HASH_KEY SD_ID128_MAKE(80,11,8c,c2,fe,4a,03,ee,3e,d6,0c,6f,36,39,14,09)

struct sd_dhcp6_client {
        RefCount n_ref;

        enum DHCP6State state;
        sd_event *event;
        int event_priority;
        int index;
        struct ether_addr mac_addr;
        DHCP6IA ia_na;
        sd_dhcp6_client_cb_t cb;
        void *userdata;

        struct duid_en {
                uint16_t type; /* DHCP6_DUID_EN */
                uint32_t pen;
                uint8_t id[8];
        } _packed_ duid;
};

int sd_dhcp6_client_set_callback(sd_dhcp6_client *client,
                                 sd_dhcp6_client_cb_t cb, void *userdata)
{
        assert_return(client, -EINVAL);

        client->cb = cb;
        client->userdata = userdata;

        return 0;
}

int sd_dhcp6_client_set_index(sd_dhcp6_client *client, int interface_index)
{
        assert_return(client, -EINVAL);
        assert_return(interface_index >= -1, -EINVAL);

        client->index = interface_index;

        return 0;
}

int sd_dhcp6_client_set_mac(sd_dhcp6_client *client,
                            const struct ether_addr *mac_addr)
{
        assert_return(client, -EINVAL);

        if (mac_addr)
                memcpy(&client->mac_addr, mac_addr, sizeof(client->mac_addr));
        else
                memset(&client->mac_addr, 0x00, sizeof(client->mac_addr));

        return 0;
}

static sd_dhcp6_client *client_notify(sd_dhcp6_client *client, int event) {
        if (client->cb) {
                client = sd_dhcp6_client_ref(client);
                client->cb(client, event, client->userdata);
                client = sd_dhcp6_client_unref(client);
        }

        return client;
}

static int client_initialize(sd_dhcp6_client *client)
{
        assert_return(client, -EINVAL);

        client->ia_na.timeout_t1 =
                sd_event_source_unref(client->ia_na.timeout_t1);
        client->ia_na.timeout_t2 =
                sd_event_source_unref(client->ia_na.timeout_t2);

        client->state = DHCP6_STATE_STOPPED;

        return 0;
}

static sd_dhcp6_client *client_stop(sd_dhcp6_client *client, int error) {
        assert_return(client, NULL);

        client = client_notify(client, error);
        if (client)
                client_initialize(client);

        return client;
}

static int client_ensure_iaid(sd_dhcp6_client *client) {
        const char *name = NULL;
        uint64_t id;

        assert(client);

        if (client->ia_na.id)
                return 0;

        if (detect_container(NULL) <= 0) {
                /* not in a container, udev will be around */
                _cleanup_udev_unref_ struct udev *udev;
                _cleanup_udev_device_unref_ struct udev_device *device;
                char ifindex_str[2 + DECIMAL_STR_MAX(int)];

                udev = udev_new();
                if (!udev)
                        return -ENOMEM;

                sprintf(ifindex_str, "n%d", client->index);
                device = udev_device_new_from_device_id(udev, ifindex_str);
                if (!device)
                        return -errno;

                if (udev_device_get_is_initialized(device) <= 0)
                        /* not yet ready */
                        return -EBUSY;

                name = net_get_name(device);
        }

        if (name)
                siphash24((uint8_t*)&id, name, strlen(name), HASH_KEY.bytes);
        else
                /* fall back to mac address if no predictable name available */
                siphash24((uint8_t*)&id, &client->mac_addr, ETH_ALEN,
                          HASH_KEY.bytes);

        /* fold into 32 bits */
        client->ia_na.id = (id & 0xffffffff) ^ (id >> 32);

        return 0;
}

static int client_start(sd_dhcp6_client *client)
{
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->index > 0, -EINVAL);

        r = client_ensure_iaid(client);
        if (r < 0)
                return r;

        return 0;
}

int sd_dhcp6_client_stop(sd_dhcp6_client *client)
{
        client_stop(client, DHCP6_EVENT_STOP);

        return 0;
}

int sd_dhcp6_client_start(sd_dhcp6_client *client)
{
        int r = 0;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->index > 0, -EINVAL);

        r = client_initialize(client);
        if (r < 0)
                return r;

        return client_start(client);
}

int sd_dhcp6_client_attach_event(sd_dhcp6_client *client, sd_event *event,
                                 int priority)
{
        int r;

        assert_return(client, -EINVAL);
        assert_return(!client->event, -EBUSY);

        if (event)
                client->event = sd_event_ref(event);
        else {
                r = sd_event_default(&client->event);
                if (r < 0)
                        return 0;
        }

        client->event_priority = priority;

        return 0;
}

int sd_dhcp6_client_detach_event(sd_dhcp6_client *client) {
        assert_return(client, -EINVAL);

        client->event = sd_event_unref(client->event);

        return 0;
}

sd_event *sd_dhcp6_client_get_event(sd_dhcp6_client *client) {
        if (!client)
                return NULL;

        return client->event;
}

sd_dhcp6_client *sd_dhcp6_client_ref(sd_dhcp6_client *client) {
        if (client)
                assert_se(REFCNT_INC(client->n_ref) >= 2);

        return client;
}

sd_dhcp6_client *sd_dhcp6_client_unref(sd_dhcp6_client *client) {
        if (client && REFCNT_DEC(client->n_ref) <= 0) {
                client_initialize(client);

                sd_dhcp6_client_detach_event(client);

                free(client);

                return NULL;
        }

        return client;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp6_client*, sd_dhcp6_client_unref);
#define _cleanup_dhcp6_client_free_ _cleanup_(sd_dhcp6_client_unrefp)

int sd_dhcp6_client_new(sd_dhcp6_client **ret)
{
        _cleanup_dhcp6_client_free_ sd_dhcp6_client *client = NULL;
        sd_id128_t machine_id;
        int r;

        assert_return(ret, -EINVAL);

        client = new0(sd_dhcp6_client, 1);
        if (!client)
                return -ENOMEM;

        client->n_ref = REFCNT_INIT;

        client->ia_na.type = DHCP6_OPTION_IA_NA;

        client->index = -1;

        /* initialize DUID */
        client->duid.type = htobe16(DHCP6_DUID_EN);
        client->duid.pen = htobe32(SYSTEMD_PEN);

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return r;

        /* a bit of snake-oil perhaps, but no need to expose the machine-id
           directly */
        siphash24(client->duid.id, &machine_id, sizeof(machine_id),
                  HASH_KEY.bytes);

        *ret = client;
        client = NULL;

        return 0;
}
