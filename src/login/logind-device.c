/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <string.h>

#include "util.h"
#include "logind-device.h"

Device* device_new(Manager *m, const char *sysfs, bool master) {
        Device *d;

        assert(m);
        assert(sysfs);

        d = new0(Device, 1);
        if (!d)
                return NULL;

        d->sysfs = strdup(sysfs);
        if (!d->sysfs) {
                free(d);
                return NULL;
        }

        if (hashmap_put(m->devices, d->sysfs, d) < 0) {
                free(d->sysfs);
                free(d);
                return NULL;
        }

        d->manager = m;
        d->master = master;
        dual_timestamp_get(&d->timestamp);

        return d;
}

static void device_detach(Device *d) {
        Seat *s;
        SessionDevice *sd;

        assert(d);

        if (!d->seat)
                return;

        while ((sd = d->session_devices))
                session_device_free(sd);

        s = d->seat;
        LIST_REMOVE(devices, d->seat->devices, d);
        d->seat = NULL;

        if (!seat_has_master_device(s)) {
                seat_add_to_gc_queue(s);
                seat_send_changed(s, "CanGraphical", NULL);
        }
}

void device_free(Device *d) {
        assert(d);

        device_detach(d);

        hashmap_remove(d->manager->devices, d->sysfs);

        free(d->sysfs);
        free(d);
}

void device_attach(Device *d, Seat *s) {
        Device *i;
        bool had_master;

        assert(d);
        assert(s);

        if (d->seat == s)
                return;

        if (d->seat)
                device_detach(d);

        d->seat = s;
        had_master = seat_has_master_device(s);

        /* We keep the device list sorted by the "master" flag. That is, master
         * devices are at the front, other devices at the tail. As there is no
         * way to easily add devices at the list-tail, we need to iterate the
         * list to find the first non-master device when adding non-master
         * devices. We assume there is only a few (normally 1) master devices
         * per seat, so we iterate only a few times. */

        if (d->master || !s->devices)
                LIST_PREPEND(devices, s->devices, d);
        else {
                LIST_FOREACH(devices, i, s->devices) {
                        if (!i->devices_next || !i->master) {
                                LIST_INSERT_AFTER(devices, s->devices, i, d);
                                break;
                        }
                }
        }

        if (!had_master && d->master)
                seat_send_changed(s, "CanGraphical", NULL);
}
