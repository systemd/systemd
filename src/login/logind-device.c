/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>

#include "alloc-util.h"
#include "logind-device.h"
#include "logind-seat-dbus.h"
#include "util.h"

Device* device_new(Manager *m, const char *sysfs, bool master) {
        Device *d;

        assert(m);
        assert(sysfs);

        d = new0(Device, 1);
        if (!d)
                return NULL;

        d->sysfs = strdup(sysfs);
        if (!d->sysfs)
                return mfree(d);

        if (hashmap_put(m->devices, d->sysfs, d) < 0) {
                free(d->sysfs);
                return mfree(d);
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

        if (!had_master && d->master && s->started) {
                seat_save(s);
                seat_send_changed(s, "CanGraphical", NULL);
        }
}
