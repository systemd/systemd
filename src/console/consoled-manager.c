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
#include "sd-bus.h"
#include "sd-event.h"
#include "sd-login.h"
#include "log.h"
#include "signal-util.h"
#include "util.h"
#include "consoled.h"
#include "idev.h"
#include "grdev.h"
#include "sysview.h"
#include "unifont.h"

int manager_new(Manager **out) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(out);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_watchdog(m->event, true);
        if (r < 0)
                return r;

        r = sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGQUIT, SIGINT, SIGWINCH, SIGCHLD, -1);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGQUIT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_bus_open_system(&m->sysbus);
        if (r < 0)
                return r;

        r = sd_bus_attach_event(m->sysbus, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        r = unifont_new(&m->uf);
        if (r < 0)
                return r;

        r = sysview_context_new(&m->sysview,
                                SYSVIEW_CONTEXT_SCAN_LOGIND |
                                SYSVIEW_CONTEXT_SCAN_EVDEV |
                                SYSVIEW_CONTEXT_SCAN_DRM,
                                m->event,
                                m->sysbus,
                                NULL);
        if (r < 0)
                return r;

        r = grdev_context_new(&m->grdev, m->event, m->sysbus);
        if (r < 0)
                return r;

        r = idev_context_new(&m->idev, m->event, m->sysbus);
        if (r < 0)
                return r;

        *out = m;
        m = NULL;
        return 0;
}

Manager *manager_free(Manager *m) {
        if (!m)
                return NULL;

        assert(!m->workspace_list);

        m->idev = idev_context_unref(m->idev);
        m->grdev = grdev_context_unref(m->grdev);
        m->sysview = sysview_context_free(m->sysview);
        m->uf = unifont_unref(m->uf);
        m->sysbus = sd_bus_unref(m->sysbus);
        m->event = sd_event_unref(m->event);
        free(m);

        return NULL;
}

static int manager_sysview_session_filter(Manager *m, sysview_event *event) {
        const char *sid = event->session_filter.id;
        _cleanup_free_ char *desktop = NULL;
        int r;

        assert(sid);

        r = sd_session_get_desktop(sid, &desktop);
        if (r < 0)
                return 0;

        return streq(desktop, "systemd-console");
}

static int manager_sysview_session_add(Manager *m, sysview_event *event) {
        sysview_session *session = event->session_add.session;
        Session *s;
        int r;

        r = sysview_session_take_control(session);
        if (r < 0)
                return log_error_errno(r, "Cannot request session control on '%s': %m",
                                       sysview_session_get_name(session));

        r = session_new(&s, m, session);
        if (r < 0) {
                log_error_errno(r, "Cannot create session on '%s': %m",
                                sysview_session_get_name(session));
                sysview_session_release_control(session);
                return r;
        }

        sysview_session_set_userdata(session, s);

        return 0;
}

static int manager_sysview_session_remove(Manager *m, sysview_event *event) {
        sysview_session *session = event->session_remove.session;
        Session *s;

        s = sysview_session_get_userdata(session);
        if (!s)
                return 0;

        session_free(s);

        return 0;
}

static int manager_sysview_session_attach(Manager *m, sysview_event *event) {
        sysview_session *session = event->session_attach.session;
        sysview_device *device = event->session_attach.device;
        Session *s;

        s = sysview_session_get_userdata(session);
        if (!s)
                return 0;

        session_add_device(s, device);

        return 0;
}

static int manager_sysview_session_detach(Manager *m, sysview_event *event) {
        sysview_session *session = event->session_detach.session;
        sysview_device *device = event->session_detach.device;
        Session *s;

        s = sysview_session_get_userdata(session);
        if (!s)
                return 0;

        session_remove_device(s, device);

        return 0;
}

static int manager_sysview_session_refresh(Manager *m, sysview_event *event) {
        sysview_session *session = event->session_refresh.session;
        sysview_device *device = event->session_refresh.device;
        struct udev_device *ud = event->session_refresh.ud;
        Session *s;

        s = sysview_session_get_userdata(session);
        if (!s)
                return 0;

        session_refresh_device(s, device, ud);

        return 0;
}

static int manager_sysview_session_control(Manager *m, sysview_event *event) {
        sysview_session *session = event->session_control.session;
        int error = event->session_control.error;
        Session *s;

        s = sysview_session_get_userdata(session);
        if (!s)
                return 0;

        if (error < 0) {
                log_error_errno(error, "Cannot take session control on '%s': %m",
                                sysview_session_get_name(session));
                session_free(s);
                sysview_session_set_userdata(session, NULL);
                return error;
        }

        return 0;
}

static int manager_sysview_fn(sysview_context *sysview, void *userdata, sysview_event *event) {
        Manager *m = userdata;
        int r;

        assert(m);

        switch (event->type) {
        case SYSVIEW_EVENT_SESSION_FILTER:
                r = manager_sysview_session_filter(m, event);
                break;
        case SYSVIEW_EVENT_SESSION_ADD:
                r = manager_sysview_session_add(m, event);
                break;
        case SYSVIEW_EVENT_SESSION_REMOVE:
                r = manager_sysview_session_remove(m, event);
                break;
        case SYSVIEW_EVENT_SESSION_ATTACH:
                r = manager_sysview_session_attach(m, event);
                break;
        case SYSVIEW_EVENT_SESSION_DETACH:
                r = manager_sysview_session_detach(m, event);
                break;
        case SYSVIEW_EVENT_SESSION_REFRESH:
                r = manager_sysview_session_refresh(m, event);
                break;
        case SYSVIEW_EVENT_SESSION_CONTROL:
                r = manager_sysview_session_control(m, event);
                break;
        default:
                r = 0;
                break;
        }

        return r;
}

int manager_run(Manager *m) {
        int r;

        assert(m);

        r = sysview_context_start(m->sysview, manager_sysview_fn, m);
        if (r < 0)
                return r;

        r = sd_event_loop(m->event);

        sysview_context_stop(m->sysview);
        return r;
}
