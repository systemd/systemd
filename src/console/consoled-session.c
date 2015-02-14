/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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
#include <stdlib.h>
#include "consoled.h"
#include "grdev.h"
#include "idev.h"
#include "list.h"
#include "macro.h"
#include "sd-event.h"
#include "sysview.h"
#include "util.h"

static bool session_feed_keyboard(Session *s, idev_data *data) {
        idev_data_keyboard *kdata = &data->keyboard;

        if (!data->resync && kdata->value == 1 && kdata->n_syms == 1) {
                uint32_t nr;
                sysview_seat *seat;

                /* handle VT-switch requests */
                nr = 0;

                switch (kdata->keysyms[0]) {
                case XKB_KEY_F1 ... XKB_KEY_F12:
                        if (IDEV_KBDMATCH(kdata,
                                          IDEV_KBDMOD_CTRL | IDEV_KBDMOD_ALT,
                                          kdata->keysyms[0]))
                                nr = kdata->keysyms[0] - XKB_KEY_F1 + 1;
                        break;
                case XKB_KEY_XF86Switch_VT_1 ... XKB_KEY_XF86Switch_VT_12:
                        nr = kdata->keysyms[0] - XKB_KEY_XF86Switch_VT_1 + 1;
                        break;
                }

                if (nr != 0) {
                        seat = sysview_session_get_seat(s->sysview);
                        sysview_seat_switch_to(seat, nr);
                        return true;
                }
        }

        return false;
}

static bool session_feed(Session *s, idev_data *data) {
        switch (data->type) {
        case IDEV_DATA_KEYBOARD:
                return session_feed_keyboard(s, data);
        default:
                return false;
        }
}

static int session_idev_fn(idev_session *idev, void *userdata, idev_event *event) {
        Session *s = userdata;

        switch (event->type) {
        case IDEV_EVENT_DEVICE_ADD:
                idev_device_enable(event->device_add.device);
                break;
        case IDEV_EVENT_DEVICE_REMOVE:
                idev_device_disable(event->device_remove.device);
                break;
        case IDEV_EVENT_DEVICE_DATA:
                if (!session_feed(s, &event->device_data.data))
                        workspace_feed(s->active_ws, &event->device_data.data);
                break;
        }

        return 0;
}

static void session_grdev_fn(grdev_session *grdev, void *userdata, grdev_event *event) {
        grdev_display *display;
        Session *s = userdata;
        Display *d;
        int r;

        switch (event->type) {
        case GRDEV_EVENT_DISPLAY_ADD:
                display = event->display_add.display;

                r = display_new(&d, s, display);
                if (r < 0) {
                        log_error_errno(r, "Cannot create display '%s' on '%s': %m",
                                        grdev_display_get_name(display), sysview_session_get_name(s->sysview));
                        break;
                }

                grdev_display_set_userdata(display, d);
                workspace_refresh(s->active_ws);
                break;
        case GRDEV_EVENT_DISPLAY_REMOVE:
                display = event->display_remove.display;
                d = grdev_display_get_userdata(display);
                if (!d)
                        break;

                display_free(d);
                workspace_refresh(s->active_ws);
                break;
        case GRDEV_EVENT_DISPLAY_CHANGE:
                display = event->display_remove.display;
                d = grdev_display_get_userdata(display);
                if (!d)
                        break;

                display_refresh(d);
                workspace_refresh(s->active_ws);
                break;
        case GRDEV_EVENT_DISPLAY_FRAME:
                display = event->display_remove.display;
                d = grdev_display_get_userdata(display);
                if (!d)
                        break;

                session_dirty(s);
                break;
        }
}

static int session_redraw_fn(sd_event_source *src, void *userdata) {
        Session *s = userdata;
        Display *d;

        LIST_FOREACH(displays_by_session, d, s->display_list)
                display_render(d, s->active_ws);

        grdev_session_commit(s->grdev);

        return 0;
}

int session_new(Session **out, Manager *m, sysview_session *session) {
        _cleanup_(session_freep) Session *s = NULL;
        int r;

        assert(out);
        assert(m);
        assert(session);

        s = new0(Session, 1);
        if (!s)
                return -ENOMEM;

        s->manager = m;
        s->sysview = session;

        r = grdev_session_new(&s->grdev,
                              m->grdev,
                              GRDEV_SESSION_MANAGED,
                              sysview_session_get_name(session),
                              session_grdev_fn,
                              s);
        if (r < 0)
                return r;

        r = idev_session_new(&s->idev,
                             m->idev,
                             IDEV_SESSION_MANAGED,
                             sysview_session_get_name(session),
                             session_idev_fn,
                             s);
        if (r < 0)
                return r;

        r = workspace_new(&s->my_ws, m);
        if (r < 0)
                return r;

        s->active_ws = workspace_attach(s->my_ws, s);

        r = sd_event_add_defer(m->event, &s->redraw_src, session_redraw_fn, s);
        if (r < 0)
                return r;

        grdev_session_enable(s->grdev);
        idev_session_enable(s->idev);

        *out = s;
        s = NULL;
        return 0;
}

Session *session_free(Session *s) {
        if (!s)
                return NULL;

        assert(!s->display_list);

        sd_event_source_unref(s->redraw_src);

        workspace_detach(s->active_ws, s);
        workspace_unref(s->my_ws);

        idev_session_free(s->idev);
        grdev_session_free(s->grdev);
        free(s);

        return NULL;
}

void session_dirty(Session *s) {
        int r;

        assert(s);

        r = sd_event_source_set_enabled(s->redraw_src, SD_EVENT_ONESHOT);
        if (r < 0)
                log_error_errno(r, "Cannot enable redraw-source: %m");
}

void session_add_device(Session *s, sysview_device *device) {
        unsigned int type;

        assert(s);
        assert(device);

        type = sysview_device_get_type(device);
        switch (type) {
        case SYSVIEW_DEVICE_DRM:
                grdev_session_add_drm(s->grdev, sysview_device_get_ud(device));
                break;
        case SYSVIEW_DEVICE_EVDEV:
                idev_session_add_evdev(s->idev, sysview_device_get_ud(device));
                break;
        }
}

void session_remove_device(Session *s, sysview_device *device) {
        unsigned int type;

        assert(s);
        assert(device);

        type = sysview_device_get_type(device);
        switch (type) {
        case SYSVIEW_DEVICE_DRM:
                grdev_session_remove_drm(s->grdev, sysview_device_get_ud(device));
                break;
        case SYSVIEW_DEVICE_EVDEV:
                idev_session_remove_evdev(s->idev, sysview_device_get_ud(device));
                break;
        }
}

void session_refresh_device(Session *s, sysview_device *device, struct udev_device *ud) {
        unsigned int type;

        assert(s);
        assert(device);

        type = sysview_device_get_type(device);
        switch (type) {
        case SYSVIEW_DEVICE_DRM:
                grdev_session_hotplug_drm(s->grdev, sysview_device_get_ud(device));
                break;
        }
}
