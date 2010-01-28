/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>
#include <libudev.h>

#include "unit.h"
#include "device.h"
#include "strv.h"
#include "log.h"

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        free(d->sysfs);
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {

        static const char* const state_table[_DEVICE_STATE_MAX] = {
                [DEVICE_DEAD] = "dead",
                [DEVICE_AVAILABLE] = "available"
        };

        Device *d = DEVICE(u);

        assert(d);

        fprintf(f,
                "%sDevice State: %s\n"
                "%sSysfs Path: %s\n",
                prefix, state_table[d->state],
                prefix, d->sysfs);
}

static int device_add_escaped_name(Unit *u, const char *dn) {
        char *e;
        int r;

        assert(u);
        assert(dn);
        assert(dn[0] == '/');

        if (!(e = unit_name_escape_path(dn+1, ".device")))
                return -ENOMEM;

        r = unit_add_name(u, e);
        free(e);

        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

static int device_process_device(Manager *m, struct udev_device *dev) {
        const char *dn, *names, *wants, *sysfs;
        Unit *u = NULL;
        int r;
        char *e, *w, *state;
        size_t l;
        bool delete;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        /* Check whether this entry is even relevant for us. */
        dn = udev_device_get_devnode(dev);
        names = udev_device_get_property_value(dev, "SYSTEMD_NAMES");
        wants = udev_device_get_property_value(dev, "SYSTEMD_WANTS");

        if (!dn && !names && !wants)
                return 0;

        /* Ok, seems kinda interesting. Now, let's see if this one
         * already exists. */

        if (!(sysfs = udev_device_get_syspath(dev)))
                return -ENOMEM;

        assert(sysfs[0] == '/');
        if (!(e = unit_name_escape_path(sysfs+1, ".device")))
                return -ENOMEM;

        if (!(u = manager_get_unit(m, e))) {
                const char *model;

                delete = true;

                if (!(u = unit_new(m))) {
                        free(e);
                        return -ENOMEM;
                }

                r = unit_add_name(u, e);
                free(e);

                if (r < 0)
                        goto fail;

                if (!(DEVICE(u)->sysfs = strdup(sysfs))) {
                        r = -ENOMEM;
                        goto fail;
                }

                if ((model = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE")) ||
                     (model = udev_device_get_property_value(dev, "ID_MODEL")))
                        if (!(u->meta.description = strdup(model))) {
                                r = -ENOMEM;
                                goto fail;
                        }

        } else {
                delete = false;
                free(e);
        }

        if (dn)
                if ((r = device_add_escaped_name(u, dn)) < 0)
                        goto fail;

        first = udev_device_get_devlinks_list_entry(dev);
        udev_list_entry_foreach(item, first)
                if ((r = device_add_escaped_name(u, udev_list_entry_get_name(item))) < 0)
                        goto fail;

        if (names) {
                FOREACH_WORD(w, l, names, state) {
                        if (!(e = strndup(w, l)))
                                goto fail;

                        r = unit_add_name(u, e);
                        free(e);

                        if (r < 0 && r != -EEXIST)
                                goto fail;
                }
        }


        if (set_isempty(u->meta.names)) {
                r = -EEXIST;
                goto fail;
        }

        if (wants) {
                FOREACH_WORD(w, l, wants, state) {
                        if (!(e = strndup(w, l)))
                                goto fail;

                        r = unit_add_dependency_by_name(u, UNIT_WANTS, e);
                        free(e);

                        if (r < 0)
                                goto fail;
                }
        }

        unit_add_to_load_queue(u);
        return 0;

fail:
        if (delete && u)
                unit_free(u);
        return r;
}

static int device_process_path(Manager *m, const char *path) {
        int r;
        struct udev_device *dev;

        assert(m);
        assert(path);

        if (!(dev = udev_device_new_from_syspath(m->udev, path))) {
                log_warning("Failed to get udev device object from udev for path %s.", path);
                return -ENOMEM;
        }

        r = device_process_device(m, dev);
        udev_device_unref(dev);
        return r;
}

static void device_shutdown(Manager *m) {
        assert(m);

        if (m->udev)
                udev_unref(m->udev);
}

static int device_enumerate(Manager *m) {
        int r;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(m);

        if (!(m->udev = udev_new()))
                return -ENOMEM;

        if (!(e = udev_enumerate_new(m->udev))) {
                r = -ENOMEM;
                goto fail;
        }

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto fail;
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first)
                device_process_path(m, udev_list_entry_get_name(item));

        udev_enumerate_unref(e);

        return 0;

fail:
        if (e)
                udev_enumerate_unref(e);

        device_shutdown(m);
        return r;
}

static UnitActiveState device_active_state(Unit *u) {
        return DEVICE(u)->state == DEVICE_DEAD ? UNIT_INACTIVE : UNIT_ACTIVE;
}

const UnitVTable device_vtable = {
        .suffix = ".device",

        .init = unit_load_fragment_and_dropin,
        .done = device_done,
        .dump = device_dump,

        .enumerate = device_enumerate,
        .shutdown = device_shutdown,

        .active_state = device_active_state
};
