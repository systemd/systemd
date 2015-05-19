/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2015 Tom Gundersen <teg@jklmen>

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


#include "sd-id128.h"
#include "libudev.h"
#include "udev-util.h"

#include "virt.h"
#include "sparse-endian.h"
#include "siphash24.h"

#include "dhcp6-protocol.h"
#include "dhcp-identifier.h"
#include "network-internal.h"

#define SYSTEMD_PEN 43793
#define HASH_KEY SD_ID128_MAKE(80,11,8c,c2,fe,4a,03,ee,3e,d6,0c,6f,36,39,14,09)

int dhcp_identifier_set_duid_en(struct duid *duid, size_t *len) {
        sd_id128_t machine_id;
        int r;

        assert(duid);
        assert(len);

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return r;

        unaligned_write_be16(&duid->type, DHCP6_DUID_EN);
        unaligned_write_be32(&duid->en.pen, SYSTEMD_PEN);

        *len = sizeof(duid->type) + sizeof(duid->en);

        /* a bit of snake-oil perhaps, but no need to expose the machine-id
           directly */
        siphash24(duid->en.id, &machine_id, sizeof(machine_id), HASH_KEY.bytes);

        return 0;
}


int dhcp_identifier_set_iaid(int ifindex, uint8_t *mac, size_t mac_len, void *_id) {
        /* name is a pointer to memory in the udev_device struct, so must
           have the same scope */
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        const char *name = NULL;
        uint64_t id;

        if (detect_container(NULL) <= 0) {
                /* not in a container, udev will be around */
                _cleanup_udev_unref_ struct udev *udev;
                char ifindex_str[2 + DECIMAL_STR_MAX(int)];

                udev = udev_new();
                if (!udev)
                        return -ENOMEM;

                sprintf(ifindex_str, "n%d", ifindex);
                device = udev_device_new_from_device_id(udev, ifindex_str);
                if (device) {
                        if (udev_device_get_is_initialized(device) <= 0)
                                /* not yet ready */
                                return -EBUSY;

                        name = net_get_name(device);
                }
        }

        if (name)
                siphash24((uint8_t*)&id, name, strlen(name), HASH_KEY.bytes);
        else
                /* fall back to MAC address if no predictable name available */
                siphash24((uint8_t*)&id, mac, mac_len, HASH_KEY.bytes);

        /* fold into 32 bits */
        unaligned_write_be32(_id, (id & 0xffffffff) ^ (id >> 32));

        return 0;
}
