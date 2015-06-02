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

#include <inttypes.h>
#include <libudev.h>
#include <stdbool.h>
#include <stdlib.h>
#include "sd-bus.h"
#include "sd-event.h"
#include "sd-login.h"
#include "macro.h"
#include "udev-util.h"
#include "util.h"
#include "bus-util.h"
#include "sysview.h"
#include "sysview-internal.h"

static int context_raise_session_control(sysview_context *c, sysview_session *session, int error);

/*
 * Devices
 */

sysview_device *sysview_find_device(sysview_context *c, const char *name) {
        assert_return(c, NULL);
        assert_return(name, NULL);

        return hashmap_get(c->device_map, name);
}

int sysview_device_new(sysview_device **out, sysview_seat *seat, const char *name) {
        _cleanup_(sysview_device_freep) sysview_device *device = NULL;
        int r;

        assert_return(seat, -EINVAL);
        assert_return(name, -EINVAL);

        device = new0(sysview_device, 1);
        if (!device)
                return -ENOMEM;

        device->seat = seat;
        device->type = (unsigned)-1;

        device->name = strdup(name);
        if (!device->name)
                return -ENOMEM;

        r = hashmap_put(seat->context->device_map, device->name, device);
        if (r < 0)
                return r;

        r = hashmap_put(seat->device_map, device->name, device);
        if (r < 0)
                return r;

        if (out)
                *out = device;
        device = NULL;
        return 0;
}

sysview_device *sysview_device_free(sysview_device *device) {
        if (!device)
                return NULL;

        if (device->name) {
                hashmap_remove_value(device->seat->device_map, device->name, device);
                hashmap_remove_value(device->seat->context->device_map, device->name, device);
        }

        switch (device->type) {
        case SYSVIEW_DEVICE_EVDEV:
                device->evdev.ud = udev_device_unref(device->evdev.ud);
                break;
        case SYSVIEW_DEVICE_DRM:
                device->drm.ud = udev_device_unref(device->drm.ud);
                break;
        }

        free(device->name);
        free(device);

        return NULL;
}

const char *sysview_device_get_name(sysview_device *device) {
        assert_return(device, NULL);

        return device->name;
}

unsigned int sysview_device_get_type(sysview_device *device) {
        assert_return(device, (unsigned)-1);

        return device->type;
}

struct udev_device *sysview_device_get_ud(sysview_device *device) {
        assert_return(device, NULL);

        switch (device->type) {
        case SYSVIEW_DEVICE_EVDEV:
                return device->evdev.ud;
        case SYSVIEW_DEVICE_DRM:
                return device->drm.ud;
        default:
                assert_return(0, NULL);
        }
}

static int device_new_ud(sysview_device **out, sysview_seat *seat, unsigned int type, struct udev_device *ud) {
        _cleanup_(sysview_device_freep) sysview_device *device = NULL;
        int r;

        assert_return(seat, -EINVAL);
        assert_return(ud, -EINVAL);

        r = sysview_device_new(&device, seat, udev_device_get_syspath(ud));
        if (r < 0)
                return r;

        device->type = type;

        switch (type) {
        case SYSVIEW_DEVICE_EVDEV:
                device->evdev.ud = udev_device_ref(ud);
                break;
        case SYSVIEW_DEVICE_DRM:
                device->drm.ud = udev_device_ref(ud);
                break;
        default:
                assert_not_reached("sysview: invalid udev-device type");
        }

        if (out)
                *out = device;
        device = NULL;
        return 0;
}

/*
 * Sessions
 */

sysview_session *sysview_find_session(sysview_context *c, const char *name) {
        assert_return(c, NULL);
        assert_return(name, NULL);

        return hashmap_get(c->session_map, name);
}

int sysview_session_new(sysview_session **out, sysview_seat *seat, const char *name) {
        _cleanup_(sysview_session_freep) sysview_session *session = NULL;
        int r;

        assert_return(seat, -EINVAL);

        session = new0(sysview_session, 1);
        if (!session)
                return -ENOMEM;

        session->seat = seat;

        if (name) {
                /*
                 * If a name is given, we require it to be a logind session
                 * name. The session will be put in managed mode and we use
                 * logind to request controller access.
                 */

                session->name = strdup(name);
                if (!session->name)
                        return -ENOMEM;

                r = sd_bus_path_encode("/org/freedesktop/login1/session",
                                       session->name, &session->path);
                if (r < 0)
                        return r;

                session->custom = false;
        } else {
                /*
                 * No session name was given. We assume this is an unmanaged
                 * session controlled by the application. We don't use logind
                 * at all and leave session management to the application. The
                 * name of the session-object is set to a unique random string
                 * that does not clash with the logind namespace.
                 */

                r = asprintf(&session->name, "@custom%" PRIu64,
                             ++seat->context->custom_sid);
                if (r < 0)
                        return -ENOMEM;

                session->custom = true;
        }

        r = hashmap_put(seat->context->session_map, session->name, session);
        if (r < 0)
                return r;

        r = hashmap_put(seat->session_map, session->name, session);
        if (r < 0)
                return r;

        if (out)
                *out = session;
        session = NULL;
        return 0;
}

sysview_session *sysview_session_free(sysview_session *session) {
        if (!session)
                return NULL;

        assert(!session->public);
        assert(!session->wants_control);

        if (session->name) {
                hashmap_remove_value(session->seat->session_map, session->name, session);
                hashmap_remove_value(session->seat->context->session_map, session->name, session);
        }

        free(session->path);
        free(session->name);
        free(session);

        return NULL;
}

void sysview_session_set_userdata(sysview_session *session, void *userdata) {
        assert(session);

        session->userdata = userdata;
}

void *sysview_session_get_userdata(sysview_session *session) {
        assert_return(session, NULL);

        return session->userdata;
}

const char *sysview_session_get_name(sysview_session *session) {
        assert_return(session, NULL);

        return session->name;
}

sysview_seat *sysview_session_get_seat(sysview_session *session) {
        assert_return(session, NULL);

        return session->seat;
}

static int session_take_control_fn(sd_bus_message *reply,
                                   void *userdata,
                                   sd_bus_error *ret_error) {
        sysview_session *session = userdata;
        int r, error;

        session->slot_take_control = sd_bus_slot_unref(session->slot_take_control);

        if (sd_bus_message_is_method_error(reply, NULL)) {
                const sd_bus_error *e = sd_bus_message_get_error(reply);

                log_debug("sysview: %s: TakeControl failed: %s: %s",
                          session->name, e->name, e->message);
                error = -sd_bus_error_get_errno(e);
        } else {
                session->has_control = true;
                error = 0;
        }

        r = context_raise_session_control(session->seat->context, session, error);
        if (r < 0)
                log_debug_errno(r, "sysview: callback failed while signalling session control '%d' on session '%s': %m",
                                error, session->name);

        return 0;
}

int sysview_session_take_control(sysview_session *session) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert_return(session, -EINVAL);
        assert_return(!session->custom, -EINVAL);

        if (session->wants_control)
                return 0;

        r = sd_bus_message_new_method_call(session->seat->context->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           session->path,
                                           "org.freedesktop.login1.Session",
                                           "TakeControl");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "b", 0);
        if (r < 0)
                return r;

        r = sd_bus_call_async(session->seat->context->sysbus,
                              &session->slot_take_control,
                              m,
                              session_take_control_fn,
                              session,
                              0);
        if (r < 0)
                return r;

        session->wants_control = true;
        return 0;
}

void sysview_session_release_control(sysview_session *session) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(session);
        assert(!session->custom);

        if (!session->wants_control)
                return;

        session->wants_control = false;

        if (!session->has_control && !session->slot_take_control)
                return;

        session->has_control = false;
        session->slot_take_control = sd_bus_slot_unref(session->slot_take_control);

        r = sd_bus_message_new_method_call(session->seat->context->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           session->path,
                                           "org.freedesktop.login1.Session",
                                           "ReleaseControl");
        if (r >= 0)
                r = sd_bus_send(session->seat->context->sysbus, m, NULL);

        if (r < 0 && r != -ENOTCONN)
                log_debug_errno(r, "sysview: %s: cannot send ReleaseControl: %m",
                                session->name);
}

/*
 * Seats
 */

sysview_seat *sysview_find_seat(sysview_context *c, const char *name) {
        assert_return(c, NULL);
        assert_return(name, NULL);

        return hashmap_get(c->seat_map, name);
}

int sysview_seat_new(sysview_seat **out, sysview_context *c, const char *name) {
        _cleanup_(sysview_seat_freep) sysview_seat *seat = NULL;
        int r;

        assert_return(c, -EINVAL);
        assert_return(name, -EINVAL);

        seat = new0(sysview_seat, 1);
        if (!seat)
                return -ENOMEM;

        seat->context = c;

        seat->name = strdup(name);
        if (!seat->name)
                return -ENOMEM;

        r = sd_bus_path_encode("/org/freedesktop/login1/seat", seat->name, &seat->path);
        if (r < 0)
                return r;

        seat->session_map = hashmap_new(&string_hash_ops);
        if (!seat->session_map)
                return -ENOMEM;

        seat->device_map = hashmap_new(&string_hash_ops);
        if (!seat->device_map)
                return -ENOMEM;

        r = hashmap_put(c->seat_map, seat->name, seat);
        if (r < 0)
                return r;

        if (out)
                *out = seat;
        seat = NULL;
        return 0;
}

sysview_seat *sysview_seat_free(sysview_seat *seat) {
        if (!seat)
                return NULL;

        assert(!seat->public);
        assert(hashmap_size(seat->device_map) == 0);
        assert(hashmap_size(seat->session_map) == 0);

        if (seat->name)
                hashmap_remove_value(seat->context->seat_map, seat->name, seat);

        hashmap_free(seat->device_map);
        hashmap_free(seat->session_map);
        free(seat->path);
        free(seat->name);
        free(seat);

        return NULL;
}

const char *sysview_seat_get_name(sysview_seat *seat) {
        assert_return(seat, NULL);

        return seat->name;
}

int sysview_seat_switch_to(sysview_seat *seat, uint32_t nr) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert_return(seat, -EINVAL);
        assert_return(seat->context->sysbus, -EINVAL);

        r = sd_bus_message_new_method_call(seat->context->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           seat->path,
                                           "org.freedesktop.login1.Seat",
                                           "SwitchTo");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "u", nr);
        if (r < 0)
                return r;

        return sd_bus_send(seat->context->sysbus, m, NULL);
}

/*
 * Contexts
 */

static int context_raise(sysview_context *c, sysview_event *event, int def) {
        return c->running ? c->event_fn(c, c->userdata, event) : def;
}

static int context_raise_settle(sysview_context *c) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SETTLE,
        };

        return context_raise(c, &event, 0);
}

static int context_raise_seat_add(sysview_context *c, sysview_seat *seat) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SEAT_ADD,
                .seat_add = {
                        .seat = seat,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_seat_remove(sysview_context *c, sysview_seat *seat) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SEAT_REMOVE,
                .seat_remove = {
                        .seat = seat,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_session_filter(sysview_context *c,
                                        const char *id,
                                        const char *seatid,
                                        const char *username,
                                        unsigned int uid) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_FILTER,
                .session_filter = {
                        .id = id,
                        .seatid = seatid,
                        .username = username,
                        .uid = uid,
                }
        };

        return context_raise(c, &event, 1);
}

static int context_raise_session_add(sysview_context *c, sysview_session *session) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_ADD,
                .session_add = {
                        .session = session,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_session_remove(sysview_context *c, sysview_session *session) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_REMOVE,
                .session_remove = {
                        .session = session,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_session_control(sysview_context *c, sysview_session *session, int error) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_CONTROL,
                .session_control = {
                        .session = session,
                        .error = error,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_session_attach(sysview_context *c, sysview_session *session, sysview_device *device) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_ATTACH,
                .session_attach = {
                        .session = session,
                        .device = device,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_session_detach(sysview_context *c, sysview_session *session, sysview_device *device) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_DETACH,
                .session_detach = {
                        .session = session,
                        .device = device,
                }
        };

        return context_raise(c, &event, 0);
}

static int context_raise_session_refresh(sysview_context *c, sysview_session *session, sysview_device *device, struct udev_device *ud) {
        sysview_event event = {
                .type = SYSVIEW_EVENT_SESSION_REFRESH,
                .session_refresh = {
                        .session = session,
                        .device = device,
                        .ud = ud,
                }
        };

        return context_raise(c, &event, 0);
}

static void context_settle(sysview_context *c) {
        int r;

        if (c->n_probe <= 0 || --c->n_probe > 0)
                return;

        log_debug("sysview: settle");

        c->settled = true;

        r = context_raise_settle(c);
        if (r < 0)
                log_debug_errno(r, "sysview: callback failed on settle: %m");
}

static void context_add_device(sysview_context *c, sysview_device *device) {
        sysview_session *session;
        Iterator i;
        int r;

        assert(c);
        assert(device);

        log_debug("sysview: add device '%s' on seat '%s'",
                  device->name, device->seat->name);

        HASHMAP_FOREACH(session, device->seat->session_map, i) {
                if (!session->public)
                        continue;

                r = context_raise_session_attach(c, session, device);
                if (r < 0)
                        log_debug_errno(r, "sysview: callback failed while attaching device '%s' to session '%s': %m",
                                        device->name, session->name);
        }
}

static void context_remove_device(sysview_context *c, sysview_device *device) {
        sysview_session *session;
        Iterator i;
        int r;

        assert(c);
        assert(device);

        log_debug("sysview: remove device '%s'", device->name);

        HASHMAP_FOREACH(session, device->seat->session_map, i) {
                if (!session->public)
                        continue;

                r = context_raise_session_detach(c, session, device);
                if (r < 0)
                        log_debug_errno(r, "sysview: callback failed while detaching device '%s' from session '%s': %m",
                                        device->name, session->name);
        }

        sysview_device_free(device);
}

static void context_change_device(sysview_context *c, sysview_device *device, struct udev_device *ud) {
        sysview_session *session;
        Iterator i;
        int r;

        assert(c);
        assert(device);

        log_debug("sysview: change device '%s'", device->name);

        HASHMAP_FOREACH(session, device->seat->session_map, i) {
                if (!session->public)
                        continue;

                r = context_raise_session_refresh(c, session, device, ud);
                if (r < 0)
                        log_debug_errno(r, "sysview: callback failed while changing device '%s' on session '%s': %m",
                                        device->name, session->name);
        }
}

static void context_add_session(sysview_context *c, sysview_seat *seat, const char *id) {
        sysview_session *session;
        sysview_device *device;
        Iterator i;
        int r;

        assert(c);
        assert(seat);
        assert(id);

        session = sysview_find_session(c, id);
        if (session)
                return;

        log_debug("sysview: add session '%s' on seat '%s'", id, seat->name);

        r = sysview_session_new(&session, seat, id);
        if (r < 0)
                goto error;

        if (!seat->scanned) {
                r = sysview_context_rescan(c);
                if (r < 0)
                        goto error;
        }

        if (seat->public) {
                session->public = true;
                r = context_raise_session_add(c, session);
                if (r < 0) {
                        log_debug_errno(r, "sysview: callback failed while adding session '%s': %m",
                                        session->name);
                        session->public = false;
                        goto error;
                }

                HASHMAP_FOREACH(device, seat->device_map, i) {
                        r = context_raise_session_attach(c, session, device);
                        if (r < 0)
                                log_debug_errno(r, "sysview: callback failed while attaching device '%s' to new session '%s': %m",
                                                device->name, session->name);
                }
        }

        return;

error:
        if (r < 0)
                log_debug_errno(r, "sysview: error while adding session '%s': %m",
                                id);
}

static void context_remove_session(sysview_context *c, sysview_session *session) {
        sysview_device *device;
        Iterator i;
        int r;

        assert(c);
        assert(session);

        log_debug("sysview: remove session '%s'", session->name);

        if (session->public) {
                HASHMAP_FOREACH(device, session->seat->device_map, i) {
                        r = context_raise_session_detach(c, session, device);
                        if (r < 0)
                                log_debug_errno(r, "sysview: callback failed while detaching device '%s' from old session '%s': %m",
                                                device->name, session->name);
                }

                session->public = false;
                r = context_raise_session_remove(c, session);
                if (r < 0)
                        log_debug_errno(r, "sysview: callback failed while removing session '%s': %m",
                                        session->name);
        }

        if (!session->custom)
                sysview_session_release_control(session);

        sysview_session_free(session);
}

static void context_add_seat(sysview_context *c, const char *id) {
        sysview_seat *seat;
        int r;

        assert(c);
        assert(id);

        seat = sysview_find_seat(c, id);
        if (seat)
                return;

        log_debug("sysview: add seat '%s'", id);

        r = sysview_seat_new(&seat, c, id);
        if (r < 0)
                goto error;

        seat->public = true;
        r = context_raise_seat_add(c, seat);
        if (r < 0) {
                log_debug_errno(r, "sysview: callback failed while adding seat '%s': %m",
                                seat->name);
                seat->public = false;
        }

        return;

error:
        if (r < 0)
                log_debug_errno(r, "sysview: error while adding seat '%s': %m",
                                id);
}

static void context_remove_seat(sysview_context *c, sysview_seat *seat) {
        sysview_session *session;
        sysview_device *device;
        int r;

        assert(c);
        assert(seat);

        log_debug("sysview: remove seat '%s'", seat->name);

        while ((device = hashmap_first(seat->device_map)))
                context_remove_device(c, device);

        while ((session = hashmap_first(seat->session_map)))
                context_remove_session(c, session);

        if (seat->public) {
                seat->public = false;
                r = context_raise_seat_remove(c, seat);
                if (r < 0)
                        log_debug_errno(r, "sysview: callback failed while removing seat '%s': %m",
                                        seat->name);
        }

        sysview_seat_free(seat);
}

int sysview_context_new(sysview_context **out,
                        unsigned int flags,
                        sd_event *event,
                        sd_bus *sysbus,
                        struct udev *ud) {
        _cleanup_(sysview_context_freep) sysview_context *c = NULL;
        int r;

        assert_return(out, -EINVAL);
        assert_return(event, -EINVAL);

        log_debug("sysview: new");

        c = new0(sysview_context, 1);
        if (!c)
                return -ENOMEM;

        c->event = sd_event_ref(event);
        if (flags & SYSVIEW_CONTEXT_SCAN_LOGIND)
                c->scan_logind = true;
        if (flags & SYSVIEW_CONTEXT_SCAN_EVDEV)
                c->scan_evdev = true;
        if (flags & SYSVIEW_CONTEXT_SCAN_DRM)
                c->scan_drm = true;

        if (sysbus) {
                c->sysbus = sd_bus_ref(sysbus);
        } else if (c->scan_logind) {
                r = sd_bus_open_system(&c->sysbus);
                if (r < 0)
                        return r;
        }

        if (ud) {
                c->ud = udev_ref(ud);
        } else if (c->scan_evdev || c->scan_drm) {
                errno = 0;
                c->ud = udev_new();
                if (!c->ud)
                        return errno > 0 ? -errno : -EFAULT;
        }

        c->seat_map = hashmap_new(&string_hash_ops);
        if (!c->seat_map)
                return -ENOMEM;

        c->session_map = hashmap_new(&string_hash_ops);
        if (!c->session_map)
                return -ENOMEM;

        c->device_map = hashmap_new(&string_hash_ops);
        if (!c->device_map)
                return -ENOMEM;

        *out = c;
        c = NULL;
        return 0;
}

sysview_context *sysview_context_free(sysview_context *c) {
        if (!c)
                return NULL;

        log_debug("sysview: free");

        sysview_context_stop(c);

        assert(hashmap_size(c->device_map) == 0);
        assert(hashmap_size(c->session_map) == 0);
        assert(hashmap_size(c->seat_map) == 0);

        hashmap_free(c->device_map);
        hashmap_free(c->session_map);
        hashmap_free(c->seat_map);
        c->ud = udev_unref(c->ud);
        c->sysbus = sd_bus_unref(c->sysbus);
        c->event = sd_event_unref(c->event);
        free(c);

        return NULL;
}

static int context_ud_prepare_monitor(sysview_context *c, struct udev_monitor *m) {
        int r;

        if (c->scan_evdev) {
                r = udev_monitor_filter_add_match_subsystem_devtype(m, "input", NULL);
                if (r < 0)
                        return r;
        }

        if (c->scan_drm) {
                r = udev_monitor_filter_add_match_subsystem_devtype(m, "drm", NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_ud_prepare_scan(sysview_context *c, struct udev_enumerate *e) {
        int r;

        if (c->scan_evdev) {
                r = udev_enumerate_add_match_subsystem(e, "input");
                if (r < 0)
                        return r;
        }

        if (c->scan_drm) {
                r = udev_enumerate_add_match_subsystem(e, "drm");
                if (r < 0)
                        return r;
        }

        r = udev_enumerate_add_match_is_initialized(e);
        if (r < 0)
                return r;

        return 0;
}

static int context_ud_hotplug(sysview_context *c, struct udev_device *d) {
        const char *syspath, *sysname, *subsystem, *action, *seatname;
        sysview_device *device;
        int r;

        syspath = udev_device_get_syspath(d);
        sysname = udev_device_get_sysname(d);
        subsystem = udev_device_get_subsystem(d);
        action = udev_device_get_action(d);

        /* not interested in custom devices without syspath/etc */
        if (!syspath || !sysname || !subsystem)
                return 0;

        device = sysview_find_device(c, syspath);

        if (streq_ptr(action, "remove")) {
                if (!device)
                        return 0;

                context_remove_device(c, device);
        } else if (streq_ptr(action, "change")) {
                if (!device)
                        return 0;

                context_change_device(c, device, d);
        } else if (!action || streq_ptr(action, "add")) {
                struct udev_device *p;
                unsigned int type, t;
                sysview_seat *seat;

                if (device)
                        return 0;

                if (streq(subsystem, "input") && startswith(sysname, "event") && safe_atou(sysname + 5, &t) >= 0)
                        type = SYSVIEW_DEVICE_EVDEV;
                else if (streq(subsystem, "drm") && startswith(sysname, "card"))
                        type = SYSVIEW_DEVICE_DRM;
                else
                        type = (unsigned)-1;

                if (type >= SYSVIEW_DEVICE_CNT)
                        return 0;

                p = d;
                seatname = NULL;
                do {
                        seatname = udev_device_get_property_value(p, "ID_SEAT");
                        if (seatname)
                                break;
                } while ((p = udev_device_get_parent(p)));

                seat = sysview_find_seat(c, seatname ? : "seat0");
                if (!seat)
                        return 0;

                r = device_new_ud(&device, seat, type, d);
                if (r < 0)
                        return log_debug_errno(r, "sysview: cannot create device for udev-device '%s': %m",
                                               syspath);

                context_add_device(c, device);
        }

        return 0;
}

static int context_ud_monitor_fn(sd_event_source *s,
                                 int fd,
                                 uint32_t revents,
                                 void *userdata) {
        sysview_context *c = userdata;
        struct udev_device *d;
        int r;

        if (revents & EPOLLIN) {
                while ((d = udev_monitor_receive_device(c->ud_monitor))) {
                        r = context_ud_hotplug(c, d);
                        udev_device_unref(d);
                        if (r != 0)
                                return r;
                }

                /* as long as EPOLLIN is signalled, read pending data */
                return 0;
        }

        if (revents & (EPOLLHUP | EPOLLERR)) {
                log_debug("sysview: HUP on udev-monitor");
                c->ud_monitor_src = sd_event_source_unref(c->ud_monitor_src);
        }

        return 0;
}

static int context_ud_start(sysview_context *c) {
        int r, fd;

        if (!c->ud)
                return 0;

        errno = 0;
        c->ud_monitor = udev_monitor_new_from_netlink(c->ud, "udev");
        if (!c->ud_monitor)
                return errno > 0 ? -errno : -EFAULT;

        r = context_ud_prepare_monitor(c, c->ud_monitor);
        if (r < 0)
                return r;

        r = udev_monitor_enable_receiving(c->ud_monitor);
        if (r < 0)
                return r;

        fd = udev_monitor_get_fd(c->ud_monitor);
        r = sd_event_add_io(c->event,
                            &c->ud_monitor_src,
                            fd,
                            EPOLLHUP | EPOLLERR | EPOLLIN,
                            context_ud_monitor_fn,
                            c);
        if (r < 0)
                return r;

        return 0;
}

static void context_ud_stop(sysview_context *c) {
        c->ud_monitor_src = sd_event_source_unref(c->ud_monitor_src);
        c->ud_monitor = udev_monitor_unref(c->ud_monitor);
}

static int context_ud_scan(sysview_context *c) {
        _cleanup_(udev_enumerate_unrefp) struct udev_enumerate *e = NULL;
        struct udev_list_entry *entry;
        struct udev_device *d;
        int r;

        if (!c->ud_monitor)
                return 0;

        errno = 0;
        e = udev_enumerate_new(c->ud);
        if (!e)
                return errno > 0 ? -errno : -EFAULT;

        r = context_ud_prepare_scan(c, e);
        if (r < 0)
                return r;

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                return r;

        udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(e)) {
                const char *name;

                name = udev_list_entry_get_name(entry);

                errno = 0;
                d = udev_device_new_from_syspath(c->ud, name);
                if (!d) {
                        r = errno > 0 ? -errno : -EFAULT;
                        log_debug_errno(r, "sysview: cannot create udev-device for %s: %m",
                                        name);
                        continue;
                }

                r = context_ud_hotplug(c, d);
                udev_device_unref(d);
                if (r != 0)
                        return r;
        }

        return 0;
}

static int context_ld_seat_new(sysview_context *c, sd_bus_message *signal) {
        const char *id, *path;
        int r;

        r = sd_bus_message_read(signal, "so", &id, &path);
        if (r < 0)
                return log_debug_errno(r, "sysview: cannot parse SeatNew from logind: %m");

        context_add_seat(c, id);
        return 0;
}

static int context_ld_seat_removed(sysview_context *c, sd_bus_message *signal) {
        const char *id, *path;
        sysview_seat *seat;
        int r;

        r = sd_bus_message_read(signal, "so", &id, &path);
        if (r < 0)
                return log_debug_errno(r, "sysview: cannot parse SeatRemoved from logind: %m");

        seat = sysview_find_seat(c, id);
        if (!seat)
                return 0;

        context_remove_seat(c, seat);
        return 0;
}

static int context_ld_session_new(sysview_context *c, sd_bus_message *signal) {
        _cleanup_free_ char *seatid = NULL, *username = NULL;
        const char *id, *path;
        sysview_seat *seat;
        uid_t uid;
        int r;

        r = sd_bus_message_read(signal, "so", &id, &path);
        if (r < 0)
                return log_debug_errno(r, "sysview: cannot parse SessionNew from logind: %m");

        /*
         * As the dbus message didn't contain enough information, we
         * read missing bits via sd-login. Note that this might race session
         * destruction, so we handle ENOENT properly.
         */

        /* ENOENT is also returned for sessions without seats */
        r = sd_session_get_seat(id, &seatid);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                goto error;

        seat = sysview_find_seat(c, seatid);
        if (!seat)
                return 0;

        r = sd_session_get_uid(id, &uid);
        if (r == -ENOENT)
                return 0;
        else if (r < 0)
                goto error;

        username = lookup_uid(uid);
        if (!username) {
                r = -ENOMEM;
                goto error;
        }

        r = context_raise_session_filter(c, id, seatid, username, uid);
        if (r < 0)
                log_debug_errno(r, "sysview: callback failed while filtering session '%s': %m",
                                id);
        else if (r > 0)
                context_add_session(c, seat, id);

        return 0;

error:
        return log_debug_errno(r, "sysview: failed retrieving information for new session '%s': %m",
                               id);
}

static int context_ld_session_removed(sysview_context *c, sd_bus_message *signal) {
        sysview_session *session;
        const char *id, *path;
        int r;

        r = sd_bus_message_read(signal, "so", &id, &path);
        if (r < 0)
                return log_debug_errno(r, "sysview: cannot parse SessionRemoved from logind: %m");

        session = sysview_find_session(c, id);
        if (!session)
                return 0;

        context_remove_session(c, session);
        return 0;
}

static int context_ld_manager_signal_fn(sd_bus_message *signal,
                                        void *userdata,
                                        sd_bus_error *ret_error) {
        sysview_context *c = userdata;

        if (sd_bus_message_is_signal(signal, "org.freedesktop.login1.Manager", "SeatNew"))
                return context_ld_seat_new(c, signal);
        else if (sd_bus_message_is_signal(signal, "org.freedesktop.login1.Manager", "SeatRemoved"))
                return context_ld_seat_removed(c, signal);
        else if (sd_bus_message_is_signal(signal, "org.freedesktop.login1.Manager", "SessionNew"))
                return context_ld_session_new(c, signal);
        else if (sd_bus_message_is_signal(signal, "org.freedesktop.login1.Manager", "SessionRemoved"))
                return context_ld_session_removed(c, signal);
        else
                return 0;
}

static int context_ld_start(sysview_context *c) {
        int r;

        if (!c->scan_logind)
                return 0;

        r = sd_bus_add_match(c->sysbus,
                             &c->ld_slot_manager_signal,
                             "type='signal',"
                             "sender='org.freedesktop.login1',"
                             "interface='org.freedesktop.login1.Manager',"
                             "path='/org/freedesktop/login1'",
                             context_ld_manager_signal_fn,
                             c);
        if (r < 0)
                return r;

        return 0;
}

static void context_ld_stop(sysview_context *c) {
        c->ld_slot_list_sessions = sd_bus_slot_unref(c->ld_slot_list_sessions);
        c->ld_slot_list_seats = sd_bus_slot_unref(c->ld_slot_list_seats);
        c->ld_slot_manager_signal = sd_bus_slot_unref(c->ld_slot_manager_signal);
}

static int context_ld_list_seats_fn(sd_bus_message *reply,
                                    void *userdata,
                                    sd_bus_error *ret_error) {
        sysview_context *c = userdata;
        int r;

        c->ld_slot_list_seats = sd_bus_slot_unref(c->ld_slot_list_seats);

        if (sd_bus_message_is_method_error(reply, NULL)) {
                const sd_bus_error *error = sd_bus_message_get_error(reply);

                log_debug("sysview: ListSeats on logind failed: %s: %s",
                          error->name, error->message);
                r = -sd_bus_error_get_errno(error);
                goto settle;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(so)");
        if (r < 0)
                goto error;

        while ((r = sd_bus_message_enter_container(reply, 'r', "so")) > 0) {
                const char *id, *path;

                r = sd_bus_message_read(reply, "so", &id, &path);
                if (r < 0)
                        goto error;

                context_add_seat(c, id);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto error;
        }

        if (r < 0)
                goto error;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto error;

        r = 0;
        goto settle;

error:
        log_debug_errno(r, "sysview: erroneous ListSeats response from logind: %m");
settle:
        context_settle(c);
        return r;
}

static int context_ld_list_sessions_fn(sd_bus_message *reply,
                                       void *userdata,
                                       sd_bus_error *ret_error) {
        sysview_context *c = userdata;
        int r;

        c->ld_slot_list_sessions = sd_bus_slot_unref(c->ld_slot_list_sessions);

        if (sd_bus_message_is_method_error(reply, NULL)) {
                const sd_bus_error *error = sd_bus_message_get_error(reply);

                log_debug("sysview: ListSessions on logind failed: %s: %s",
                          error->name, error->message);
                r = -sd_bus_error_get_errno(error);
                goto settle;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(susso)");
        if (r < 0)
                goto error;

        while ((r = sd_bus_message_enter_container(reply, 'r', "susso")) > 0) {
                const char *id, *username, *seatid, *path;
                sysview_seat *seat;
                unsigned int uid;

                r = sd_bus_message_read(reply,
                                        "susso",
                                        &id,
                                        &uid,
                                        &username,
                                        &seatid,
                                        &path);
                if (r < 0)
                        goto error;

                seat = sysview_find_seat(c, seatid);
                if (seat) {
                        r = context_raise_session_filter(c, id, seatid, username, uid);
                        if (r < 0)
                                log_debug_errno(r, "sysview: callback failed while filtering session '%s': %m",
                                                id);
                        else if (r > 0)
                                context_add_session(c, seat, id);
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto error;
        }

        if (r < 0)
                goto error;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto error;

        r = 0;
        goto settle;

error:
        log_debug_errno(r, "sysview: erroneous ListSessions response from logind: %m");
settle:
        context_settle(c);
        return r;
}

static int context_ld_scan(sysview_context *c) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        if (!c->ld_slot_manager_signal)
                return 0;

        /* request seat list */

        r = sd_bus_message_new_method_call(c->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           "/org/freedesktop/login1",
                                           "org.freedesktop.login1.Manager",
                                           "ListSeats");
        if (r < 0)
                return r;

        r = sd_bus_call_async(c->sysbus,
                              &c->ld_slot_list_seats,
                              m,
                              context_ld_list_seats_fn,
                              c,
                              0);
        if (r < 0)
                return r;

        if (!c->settled)
                ++c->n_probe;

        /* request session list */

        m = sd_bus_message_unref(m);
        r = sd_bus_message_new_method_call(c->sysbus,
                                           &m,
                                           "org.freedesktop.login1",
                                           "/org/freedesktop/login1",
                                           "org.freedesktop.login1.Manager",
                                           "ListSessions");
        if (r < 0)
                return r;

        r = sd_bus_call_async(c->sysbus,
                              &c->ld_slot_list_sessions,
                              m,
                              context_ld_list_sessions_fn,
                              c,
                              0);
        if (r < 0)
                return r;

        if (!c->settled)
                ++c->n_probe;

        return 0;
}

bool sysview_context_is_running(sysview_context *c) {
        return c && c->running;
}

int sysview_context_start(sysview_context *c, sysview_event_fn event_fn, void *userdata) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(event_fn, -EINVAL);

        if (c->running)
                return -EALREADY;

        log_debug("sysview: start");

        c->running = true;
        c->event_fn = event_fn;
        c->userdata = userdata;

        r = context_ld_start(c);
        if (r < 0)
                goto error;

        r = context_ud_start(c);
        if (r < 0)
                goto error;

        r = sysview_context_rescan(c);
        if (r < 0)
                goto error;

        return 0;

error:
        sysview_context_stop(c);
        return r;
}

void sysview_context_stop(sysview_context *c) {
        sysview_session *session;
        sysview_device *device;
        sysview_seat *seat;

        assert(c);

        if (!c->running)
                return;

        log_debug("sysview: stop");

        while ((device = hashmap_first(c->device_map)))
                context_remove_device(c, device);

        while ((session = hashmap_first(c->session_map)))
                context_remove_session(c, session);

        while ((seat = hashmap_first(c->seat_map)))
                context_remove_seat(c, seat);

        c->running = false;
        c->scanned = false;
        c->settled = false;
        c->n_probe = 0;
        c->event_fn = NULL;
        c->userdata = NULL;
        c->scan_src = sd_event_source_unref(c->scan_src);
        context_ud_stop(c);
        context_ld_stop(c);
}

static int context_scan_fn(sd_event_source *s, void *userdata) {
        sysview_context *c = userdata;
        sysview_seat *seat;
        Iterator i;
        int r;

        c->rescan = false;

        if (!c->scanned) {
                r = context_ld_scan(c);
                if (r < 0)
                        return log_debug_errno(r, "sysview: logind scan failed: %m");
        }

        /* skip device scans if no sessions are available */
        if (hashmap_size(c->session_map) > 0) {
                r = context_ud_scan(c);
                if (r < 0)
                        return log_debug_errno(r, "sysview: udev scan failed: %m");

                HASHMAP_FOREACH(seat, c->seat_map, i)
                        seat->scanned = true;
        }

        c->scanned = true;
        context_settle(c);

        return 0;
}

int sysview_context_rescan(sysview_context *c) {
        assert(c);

        if (!c->running)
                return 0;

        if (!c->rescan) {
                c->rescan = true;
                if (!c->settled)
                        ++c->n_probe;
        }

        if (c->scan_src)
                return sd_event_source_set_enabled(c->scan_src, SD_EVENT_ONESHOT);
        else
                return sd_event_add_defer(c->event, &c->scan_src, context_scan_fn, c);
}
