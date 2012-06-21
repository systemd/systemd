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

#include <assert.h>
#include <string.h>

#include "logind-device.h"
#include "util.h"

Device* device_new(Manager *m, const char *sysfs) {
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
        dual_timestamp_get(&d->timestamp);

        return d;
}

void device_free(Device *d) {
        assert(d);

        device_detach(d);

        hashmap_remove(d->manager->devices, d->sysfs);

        free(d->sysfs);
        free(d);
}

void device_detach(Device *d) {
        Seat *s;
        assert(d);

        if (!d->seat)
                return;

        s = d->seat;
        LIST_REMOVE(Device, devices, d->seat->devices, d);
        d->seat = NULL;

        seat_add_to_gc_queue(s);
        seat_send_changed(s, "CanGraphical\0");
}

void device_attach(Device *d, Seat *s) {
        assert(d);
        assert(s);

        if (d->seat == s)
                return;

        if (d->seat)
                device_detach(d);

        d->seat = s;
        LIST_PREPEND(Device, devices, s->devices, d);

        seat_send_changed(s, "CanGraphical\0");
}
