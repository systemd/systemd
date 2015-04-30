/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

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

#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include "hashmap.h"
#include "idev.h"
#include "idev-internal.h"
#include "login-shared.h"
#include "macro.h"
#include "util.h"

static void element_open(idev_element *e);
static void element_close(idev_element *e);

/*
 * Devices
 */

idev_device *idev_find_device(idev_session *s, const char *name) {
        assert_return(s, NULL);
        assert_return(name, NULL);

        return hashmap_get(s->device_map, name);
}

int idev_device_add(idev_device *d, const char *name) {
        int r;

        assert_return(d, -EINVAL);
        assert_return(d->vtable, -EINVAL);
        assert_return(d->session, -EINVAL);
        assert_return(name, -EINVAL);

        d->name = strdup(name);
        if (!d->name)
                return -ENOMEM;

        r = hashmap_put(d->session->device_map, d->name, d);
        if (r < 0)
                return r;

        return 0;
}

idev_device *idev_device_free(idev_device *d) {
        idev_device tmp;

        if (!d)
                return NULL;

        assert(!d->enabled);
        assert(!d->public);
        assert(!d->links);
        assert(d->vtable);
        assert(d->vtable->free);

        if (d->name)
                hashmap_remove_value(d->session->device_map, d->name, d);

        tmp = *d;
        d->vtable->free(d);

        free(tmp.name);

        return NULL;
}

int idev_device_feed(idev_device *d, idev_data *data) {
        assert(d);
        assert(data);
        assert(data->type < IDEV_DATA_CNT);

        if (d->vtable->feed)
                return d->vtable->feed(d, data);
        else
                return 0;
}

void idev_device_feedback(idev_device *d, idev_data *data) {
        idev_link *l;

        assert(d);
        assert(data);
        assert(data->type < IDEV_DATA_CNT);

        LIST_FOREACH(links_by_device, l, d->links)
                idev_element_feedback(l->element, data);
}

static void device_attach(idev_device *d, idev_link *l) {
        assert(d);
        assert(l);

        if (d->vtable->attach)
                d->vtable->attach(d, l);

        if (d->enabled)
                element_open(l->element);
}

static void device_detach(idev_device *d, idev_link *l) {
        assert(d);
        assert(l);

        if (d->enabled)
                element_close(l->element);

        if (d->vtable->detach)
                d->vtable->detach(d, l);
}

void idev_device_enable(idev_device *d) {
        idev_link *l;

        assert(d);

        if (!d->enabled) {
                d->enabled = true;
                LIST_FOREACH(links_by_device, l, d->links)
                        element_open(l->element);
        }
}

void idev_device_disable(idev_device *d) {
        idev_link *l;

        assert(d);

        if (d->enabled) {
                d->enabled = false;
                LIST_FOREACH(links_by_device, l, d->links)
                        element_close(l->element);
        }
}

/*
 * Elements
 */

idev_element *idev_find_element(idev_session *s, const char *name) {
        assert_return(s, NULL);
        assert_return(name, NULL);

        return hashmap_get(s->element_map, name);
}

int idev_element_add(idev_element *e, const char *name) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e->vtable, -EINVAL);
        assert_return(e->session, -EINVAL);
        assert_return(name, -EINVAL);

        e->name = strdup(name);
        if (!e->name)
                return -ENOMEM;

        r = hashmap_put(e->session->element_map, e->name, e);
        if (r < 0)
                return r;

        return 0;
}

idev_element *idev_element_free(idev_element *e) {
        idev_element tmp;

        if (!e)
                return NULL;

        assert(!e->enabled);
        assert(!e->links);
        assert(e->n_open == 0);
        assert(e->vtable);
        assert(e->vtable->free);

        if (e->name)
                hashmap_remove_value(e->session->element_map, e->name, e);

        tmp = *e;
        e->vtable->free(e);

        free(tmp.name);

        return NULL;
}

int idev_element_feed(idev_element *e, idev_data *data) {
        int r, error = 0;
        idev_link *l;

        assert(e);
        assert(data);
        assert(data->type < IDEV_DATA_CNT);

        LIST_FOREACH(links_by_element, l, e->links) {
                r = idev_device_feed(l->device, data);
                if (r != 0)
                        error = r;
        }

        return error;
}

void idev_element_feedback(idev_element *e, idev_data *data) {
        assert(e);
        assert(data);
        assert(data->type < IDEV_DATA_CNT);

        if (e->vtable->feedback)
               e->vtable->feedback(e, data);
}

static void element_open(idev_element *e) {
        assert(e);

        if (e->n_open++ == 0 && e->vtable->open)
                e->vtable->open(e);
}

static void element_close(idev_element *e) {
        assert(e);
        assert(e->n_open > 0);

        if (--e->n_open == 0 && e->vtable->close)
                e->vtable->close(e);
}

static void element_enable(idev_element *e) {
        assert(e);

        if (!e->enabled) {
                e->enabled = true;
                if (e->vtable->enable)
                        e->vtable->enable(e);
        }
}

static void element_disable(idev_element *e) {
        assert(e);

        if (e->enabled) {
                e->enabled = false;
                if (e->vtable->disable)
                        e->vtable->disable(e);
        }
}

static void element_resume(idev_element *e, int fd) {
        assert(e);
        assert(fd >= 0);

        if (e->vtable->resume)
                e->vtable->resume(e, fd);
}

static void element_pause(idev_element *e, const char *mode) {
        assert(e);
        assert(mode);

        if (e->vtable->pause)
                e->vtable->pause(e, mode);
}

/*
 * Sessions
 */

static int session_raise(idev_session *s, idev_event *ev) {
        return s->event_fn(s, s->userdata, ev);
}

static int session_raise_device_add(idev_session *s, idev_device *d) {
        idev_event event = {
                .type = IDEV_EVENT_DEVICE_ADD,
                .device_add = {
                        .device = d,
                },
        };

        return session_raise(s, &event);
}

static int session_raise_device_remove(idev_session *s, idev_device *d) {
        idev_event event = {
                .type = IDEV_EVENT_DEVICE_REMOVE,
                .device_remove = {
                        .device = d,
                },
        };

        return session_raise(s, &event);
}

int idev_session_raise_device_data(idev_session *s, idev_device *d, idev_data *data) {
        idev_event event = {
                .type = IDEV_EVENT_DEVICE_DATA,
                .device_data = {
                        .device = d,
                        .data = *data,
                },
        };

        return session_raise(s, &event);
}

static int session_add_device(idev_session *s, idev_device *d) {
        int r;

        assert(s);
        assert(d);

        log_debug("idev: %s: add device '%s'", s->name, d->name);

        d->public = true;
        r = session_raise_device_add(s, d);
        if (r != 0) {
                d->public = false;
                goto error;
        }

        return 0;

error:
        if (r < 0)
                log_debug_errno(r, "idev: %s: error while adding device '%s': %m",
                                s->name, d->name);
        return r;
}

static int session_remove_device(idev_session *s, idev_device *d) {
        int r, error = 0;

        assert(s);
        assert(d);

        log_debug("idev: %s: remove device '%s'", s->name, d->name);

        d->public = false;
        r = session_raise_device_remove(s, d);
        if (r != 0)
                error = r;

        idev_device_disable(d);

        if (error < 0)
                log_debug_errno(error, "idev: %s: error while removing device '%s': %m",
                                s->name, d->name);
        idev_device_free(d);
        return error;
}

static int session_add_element(idev_session *s, idev_element *e) {
        assert(s);
        assert(e);

        log_debug("idev: %s: add element '%s'", s->name, e->name);

        if (s->enabled)
                element_enable(e);

        return 0;
}

static int session_remove_element(idev_session *s, idev_element *e) {
        int r, error = 0;
        idev_device *d;
        idev_link *l;

        assert(s);
        assert(e);

        log_debug("idev: %s: remove element '%s'", s->name, e->name);

        while ((l = e->links)) {
                d = l->device;
                LIST_REMOVE(links_by_device, d->links, l);
                LIST_REMOVE(links_by_element, e->links, l);
                device_detach(d, l);

                if (!d->links) {
                        r = session_remove_device(s, d);
                        if (r != 0)
                                error = r;
                }

                l->device = NULL;
                l->element = NULL;
                free(l);
        }

        element_disable(e);

        if (error < 0)
                log_debug_errno(r, "idev: %s: error while removing element '%s': %m",
                                s->name, e->name);
        idev_element_free(e);
        return error;
}

idev_session *idev_find_session(idev_context *c, const char *name) {
        assert_return(c, NULL);
        assert_return(name, NULL);

        return hashmap_get(c->session_map, name);
}

static int session_resume_device_fn(sd_bus_message *signal,
                                    void *userdata,
                                    sd_bus_error *ret_error) {
        idev_session *s = userdata;
        idev_element *e;
        uint32_t major, minor;
        int r, fd;

        r = sd_bus_message_read(signal, "uuh", &major, &minor, &fd);
        if (r < 0) {
                log_debug("idev: %s: erroneous ResumeDevice signal", s->name);
                return 0;
        }

        e = idev_find_evdev(s, makedev(major, minor));
        if (!e)
                return 0;

        element_resume(e, fd);
        return 0;
}

static int session_pause_device_fn(sd_bus_message *signal,
                                   void *userdata,
                                   sd_bus_error *ret_error) {
        idev_session *s = userdata;
        idev_element *e;
        uint32_t major, minor;
        const char *mode;
        int r;

        r = sd_bus_message_read(signal, "uus", &major, &minor, &mode);
        if (r < 0) {
                log_debug("idev: %s: erroneous PauseDevice signal", s->name);
                return 0;
        }

        e = idev_find_evdev(s, makedev(major, minor));
        if (!e)
                return 0;

        element_pause(e, mode);
        return 0;
}

static int session_setup_bus(idev_session *s) {
        _cleanup_free_ char *match = NULL;
        int r;

        if (!s->managed)
                return 0;

        match = strjoin("type='signal',"
                        "sender='org.freedesktop.login1',"
                        "interface='org.freedesktop.login1.Session',"
                        "member='ResumeDevice',"
                        "path='", s->path, "'",
                        NULL);
        if (!match)
                return -ENOMEM;

        r = sd_bus_add_match(s->context->sysbus,
                             &s->slot_resume_device,
                             match,
                             session_resume_device_fn,
                             s);
        if (r < 0)
                return r;

        free(match);
        match = strjoin("type='signal',"
                        "sender='org.freedesktop.login1',"
                        "interface='org.freedesktop.login1.Session',"
                        "member='PauseDevice',"
                        "path='", s->path, "'",
                        NULL);
        if (!match)
                return -ENOMEM;

        r = sd_bus_add_match(s->context->sysbus,
                             &s->slot_pause_device,
                             match,
                             session_pause_device_fn,
                             s);
        if (r < 0)
                return r;

        return 0;
}

int idev_session_new(idev_session **out,
                     idev_context *c,
                     unsigned int flags,
                     const char *name,
                     idev_event_fn event_fn,
                     void *userdata) {
        _cleanup_(idev_session_freep) idev_session *s = NULL;
        int r;

        assert_return(out, -EINVAL);
        assert_return(c, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(event_fn, -EINVAL);
        assert_return((flags & IDEV_SESSION_CUSTOM) == !session_id_valid(name), -EINVAL);
        assert_return(!(flags & IDEV_SESSION_CUSTOM) || !(flags & IDEV_SESSION_MANAGED), -EINVAL);
        assert_return(!(flags & IDEV_SESSION_MANAGED) || c->sysbus, -EINVAL);

        s = new0(idev_session, 1);
        if (!s)
                return -ENOMEM;

        s->context = idev_context_ref(c);
        s->custom = flags & IDEV_SESSION_CUSTOM;
        s->managed = flags & IDEV_SESSION_MANAGED;
        s->event_fn = event_fn;
        s->userdata = userdata;

        s->name = strdup(name);
        if (!s->name)
                return -ENOMEM;

        if (s->managed) {
                r = sd_bus_path_encode("/org/freedesktop/login1/session", s->name, &s->path);
                if (r < 0)
                        return r;
        }

        s->element_map = hashmap_new(&string_hash_ops);
        if (!s->element_map)
                return -ENOMEM;

        s->device_map = hashmap_new(&string_hash_ops);
        if (!s->device_map)
                return -ENOMEM;

        r = session_setup_bus(s);
        if (r < 0)
                return r;

        r = hashmap_put(c->session_map, s->name, s);
        if (r < 0)
                return r;

        *out = s;
        s = NULL;
        return 0;
}

idev_session *idev_session_free(idev_session *s) {
        idev_element *e;

        if (!s)
                return NULL;

        while ((e = hashmap_first(s->element_map)))
                session_remove_element(s, e);

        assert(hashmap_size(s->device_map) == 0);

        if (s->name)
                hashmap_remove_value(s->context->session_map, s->name, s);

        s->slot_pause_device = sd_bus_slot_unref(s->slot_pause_device);
        s->slot_resume_device = sd_bus_slot_unref(s->slot_resume_device);
        s->context = idev_context_unref(s->context);
        hashmap_free(s->device_map);
        hashmap_free(s->element_map);
        free(s->path);
        free(s->name);
        free(s);

        return NULL;
}

bool idev_session_is_enabled(idev_session *s) {
        return s && s->enabled;
}

void idev_session_enable(idev_session *s) {
        idev_element *e;
        Iterator i;

        assert(s);

        if (!s->enabled) {
                s->enabled = true;
                HASHMAP_FOREACH(e, s->element_map, i)
                        element_enable(e);
        }
}

void idev_session_disable(idev_session *s) {
        idev_element *e;
        Iterator i;

        assert(s);

        if (s->enabled) {
                s->enabled = false;
                HASHMAP_FOREACH(e, s->element_map, i)
                        element_disable(e);
        }
}

static int add_link(idev_element *e, idev_device *d) {
        idev_link *l;

        assert(e);
        assert(d);

        l = new0(idev_link, 1);
        if (!l)
                return -ENOMEM;

        l->element = e;
        l->device = d;
        LIST_PREPEND(links_by_element, e->links, l);
        LIST_PREPEND(links_by_device, d->links, l);
        device_attach(d, l);

        return 0;
}

static int guess_type(struct udev_device *d) {
        const char *id_key;

        id_key = udev_device_get_property_value(d, "ID_INPUT_KEY");
        if (streq_ptr(id_key, "1"))
                return IDEV_DEVICE_KEYBOARD;

        return IDEV_DEVICE_CNT;
}

int idev_session_add_evdev(idev_session *s, struct udev_device *ud) {
        idev_element *e;
        idev_device *d;
        dev_t devnum;
        int r, type;

        assert_return(s, -EINVAL);
        assert_return(ud, -EINVAL);

        devnum = udev_device_get_devnum(ud);
        if (devnum == 0)
                return 0;

        e = idev_find_evdev(s, devnum);
        if (e)
                return 0;

        r = idev_evdev_new(&e, s, ud);
        if (r < 0)
                return r;

        r = session_add_element(s, e);
        if (r != 0)
                return r;

        type = guess_type(ud);
        if (type < 0)
                return type;

        switch (type) {
        case IDEV_DEVICE_KEYBOARD:
                d = idev_find_keyboard(s, e->name);
                if (d) {
                        log_debug("idev: %s: keyboard for new evdev element '%s' already available",
                                  s->name, e->name);
                        return 0;
                }

                r = idev_keyboard_new(&d, s, e->name);
                if (r < 0)
                        return r;

                r = add_link(e, d);
                if (r < 0) {
                        idev_device_free(d);
                        return r;
                }

                return session_add_device(s, d);
        default:
                /* unknown elements are silently ignored */
                return 0;
        }
}

int idev_session_remove_evdev(idev_session *s, struct udev_device *ud) {
        idev_element *e;
        dev_t devnum;

        assert(s);
        assert(ud);

        devnum = udev_device_get_devnum(ud);
        if (devnum == 0)
                return 0;

        e = idev_find_evdev(s, devnum);
        if (!e)
                return 0;

        return session_remove_element(s, e);
}

/*
 * Contexts
 */

int idev_context_new(idev_context **out, sd_event *event, sd_bus *sysbus) {
        _cleanup_(idev_context_unrefp) idev_context *c = NULL;

        assert_return(out, -EINVAL);
        assert_return(event, -EINVAL);

        c = new0(idev_context, 1);
        if (!c)
                return -ENOMEM;

        c->ref = 1;
        c->event = sd_event_ref(event);

        if (sysbus)
                c->sysbus = sd_bus_ref(sysbus);

        c->session_map = hashmap_new(&string_hash_ops);
        if (!c->session_map)
                return -ENOMEM;

        c->data_map = hashmap_new(&string_hash_ops);
        if (!c->data_map)
                return -ENOMEM;

        *out = c;
        c = NULL;
        return 0;
}

static void context_cleanup(idev_context *c) {
        assert(hashmap_size(c->data_map) == 0);
        assert(hashmap_size(c->session_map) == 0);

        hashmap_free(c->data_map);
        hashmap_free(c->session_map);
        c->sysbus = sd_bus_unref(c->sysbus);
        c->event = sd_event_unref(c->event);
        free(c);
}

idev_context *idev_context_ref(idev_context *c) {
        assert_return(c, NULL);
        assert_return(c->ref > 0, NULL);

        ++c->ref;
        return c;
}

idev_context *idev_context_unref(idev_context *c) {
        if (!c)
                return NULL;

        assert_return(c->ref > 0, NULL);

        if (--c->ref == 0)
                context_cleanup(c);

        return NULL;
}
