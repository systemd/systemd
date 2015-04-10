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

/*
 * Modeset Testing
 * The modeset tool attaches to the session of the caller and shows a
 * test-pattern on all displays of this session. It is meant as debugging tool
 * for the grdev infrastructure.
 */

#include <drm_fourcc.h>
#include <errno.h>
#include <getopt.h>
#include <linux/kd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <systemd/sd-login.h>
#include <termios.h>
#include <unistd.h>

#include "build.h"
#include "grdev.h"
#include "macro.h"
#include "sysview.h"
#include "util.h"
#include "random-util.h"

typedef struct Modeset Modeset;

struct Modeset {
        char *session;
        char *seat;
        sd_event *event;
        sd_bus *bus;
        sd_event_source *exit_src;
        sysview_context *sysview;
        grdev_context *grdev;
        grdev_session *grdev_session;

        uint8_t r, g, b;
        bool r_up, g_up, b_up;

        bool my_tty : 1;
        bool managed : 1;
};

static int modeset_exit_fn(sd_event_source *source, void *userdata) {
        Modeset *m = userdata;

        if (m->grdev_session)
                grdev_session_restore(m->grdev_session);

        return 0;
}

static Modeset *modeset_free(Modeset *m) {
        if (!m)
                return NULL;

        m->grdev_session = grdev_session_free(m->grdev_session);
        m->grdev = grdev_context_unref(m->grdev);
        m->sysview = sysview_context_free(m->sysview);
        m->exit_src = sd_event_source_unref(m->exit_src);
        m->bus = sd_bus_unref(m->bus);
        m->event = sd_event_unref(m->event);
        free(m->seat);
        free(m->session);
        free(m);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Modeset*, modeset_free);

static bool is_my_tty(const char *session) {
        unsigned int vtnr;
        struct stat st;
        long mode;
        int r;

        /* Using logind's Controller API is highly fragile if there is already
         * a session controller running. If it is registered as controller
         * itself, TakeControl will simply fail. But if its a legacy controller
         * that does not use logind's controller API, we must never register
         * our own controller. Otherwise, we really mess up the VT. Therefore,
         * only run in managed mode if there's no-one else.  Furthermore, never
         * try to access graphics devices if there's someone else. Unlike input
         * devices, graphics devies cannot be shared easily. */

        if (!isatty(1))
                return false;

        if (!session)
                return false;

        r = sd_session_get_vt(session, &vtnr);
        if (r < 0 || vtnr < 1 || vtnr > 63)
                return false;

        mode = 0;
        r = ioctl(1, KDGETMODE, &mode);
        if (r < 0 || mode != KD_TEXT)
                return false;

        r = fstat(1, &st);
        if (r < 0 || minor(st.st_rdev) != vtnr)
                return false;

        return true;
}

static int modeset_new(Modeset **out) {
        _cleanup_(modeset_freep) Modeset *m = NULL;
        int r;

        assert(out);

        m = new0(Modeset, 1);
        if (!m)
                return log_oom();

        r = sd_pid_get_session(getpid(), &m->session);
        if (r < 0)
                return log_error_errno(r, "Cannot retrieve logind session: %m");

        r = sd_session_get_seat(m->session, &m->seat);
        if (r < 0)
                return log_error_errno(r, "Cannot retrieve seat of logind session: %m");

        m->my_tty = is_my_tty(m->session);
        m->managed = m->my_tty && geteuid() > 0;

        m->r = rand() % 0xff;
        m->g = rand() % 0xff;
        m->b = rand() % 0xff;
        m->r_up = m->g_up = m->b_up = true;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_bus_open_system(&m->bus);
        if (r < 0)
                return r;

        r = sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        r = sigprocmask_many(SIG_BLOCK, SIGTERM, SIGINT, -1);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_exit(m->event, &m->exit_src, modeset_exit_fn, m);
        if (r < 0)
                return r;

        /* schedule before sd-bus close */
        r = sd_event_source_set_priority(m->exit_src, -10);
        if (r < 0)
                return r;

        r = sysview_context_new(&m->sysview,
                                SYSVIEW_CONTEXT_SCAN_LOGIND |
                                SYSVIEW_CONTEXT_SCAN_DRM,
                                m->event,
                                m->bus,
                                NULL);
        if (r < 0)
                return r;

        r = grdev_context_new(&m->grdev, m->event, m->bus);
        if (r < 0)
                return r;

        *out = m;
        m = NULL;
        return 0;
}

static uint8_t next_color(bool *up, uint8_t cur, unsigned int mod) {
        uint8_t next;

        /* generate smoothly morphing colors */

        next = cur + (*up ? 1 : -1) * (rand() % mod);
        if ((*up && next < cur) || (!*up && next > cur)) {
                *up = !*up;
                next = cur;
        }

        return next;
}

static void modeset_draw(Modeset *m, const grdev_display_target *t) {
        uint32_t j, k, *b;
        uint8_t *l;

        assert(t->back->format == DRM_FORMAT_XRGB8888 || t->back->format == DRM_FORMAT_ARGB8888);
        assert(!t->rotate);
        assert(!t->flip);

        l = t->back->maps[0];
        for (j = 0; j < t->height; ++j) {
                for (k = 0; k < t->width; ++k) {
                        b = (uint32_t*)l;
                        b[k] = (0xff << 24) | (m->r << 16) | (m->g << 8) | m->b;
                }

                l += t->back->strides[0];
        }
}

static void modeset_render(Modeset *m, grdev_display *d) {
        const grdev_display_target *t;

        m->r = next_color(&m->r_up, m->r, 4);
        m->g = next_color(&m->g_up, m->g, 3);
        m->b = next_color(&m->b_up, m->b, 2);

        GRDEV_DISPLAY_FOREACH_TARGET(d, t) {
                modeset_draw(m, t);
                grdev_display_flip_target(d, t);
        }

        grdev_session_commit(m->grdev_session);
}

static void modeset_grdev_fn(grdev_session *session, void *userdata, grdev_event *ev) {
        Modeset *m = userdata;

        switch (ev->type) {
        case GRDEV_EVENT_DISPLAY_ADD:
                grdev_display_enable(ev->display_add.display);
                break;
        case GRDEV_EVENT_DISPLAY_REMOVE:
                break;
        case GRDEV_EVENT_DISPLAY_CHANGE:
                break;
        case GRDEV_EVENT_DISPLAY_FRAME:
                modeset_render(m, ev->display_frame.display);
                break;
        }
}

static int modeset_sysview_fn(sysview_context *c, void *userdata, sysview_event *ev) {
        unsigned int flags, type;
        Modeset *m = userdata;
        sysview_device *d;
        const char *name;
        int r;

        switch (ev->type) {
        case SYSVIEW_EVENT_SESSION_FILTER:
                if (streq_ptr(m->session, ev->session_filter.id))
                        return 1;

                break;
        case SYSVIEW_EVENT_SESSION_ADD:
                assert(!m->grdev_session);

                name = sysview_session_get_name(ev->session_add.session);
                flags = 0;

                if (m->managed)
                        flags |= GRDEV_SESSION_MANAGED;

                r = grdev_session_new(&m->grdev_session,
                                      m->grdev,
                                      flags,
                                      name,
                                      modeset_grdev_fn,
                                      m);
                if (r < 0)
                        return log_error_errno(r, "Cannot create grdev session: %m");

                if (m->managed) {
                        r = sysview_session_take_control(ev->session_add.session);
                        if (r < 0)
                                return log_error_errno(r, "Cannot request session control: %m");
                }

                grdev_session_enable(m->grdev_session);

                break;
        case SYSVIEW_EVENT_SESSION_REMOVE:
                if (!m->grdev_session)
                        return 0;

                grdev_session_restore(m->grdev_session);
                grdev_session_disable(m->grdev_session);
                m->grdev_session = grdev_session_free(m->grdev_session);
                if (sd_event_get_exit_code(m->event, &r) == -ENODATA)
                        sd_event_exit(m->event, 0);
                break;
        case SYSVIEW_EVENT_SESSION_ATTACH:
                d = ev->session_attach.device;
                type = sysview_device_get_type(d);
                if (type == SYSVIEW_DEVICE_DRM)
                        grdev_session_add_drm(m->grdev_session, sysview_device_get_ud(d));

                break;
        case SYSVIEW_EVENT_SESSION_DETACH:
                d = ev->session_detach.device;
                type = sysview_device_get_type(d);
                if (type == SYSVIEW_DEVICE_DRM)
                        grdev_session_remove_drm(m->grdev_session, sysview_device_get_ud(d));

                break;
        case SYSVIEW_EVENT_SESSION_REFRESH:
                d = ev->session_refresh.device;
                type = sysview_device_get_type(d);
                if (type == SYSVIEW_DEVICE_DRM)
                        grdev_session_hotplug_drm(m->grdev_session, ev->session_refresh.ud);

                break;
        case SYSVIEW_EVENT_SESSION_CONTROL:
                r = ev->session_control.error;
                if (r < 0)
                        return log_error_errno(r, "Cannot acquire session control: %m");

                r = ioctl(1, KDSKBMODE, K_UNICODE);
                if (r < 0)
                        return log_error_errno(errno, "Cannot set K_UNICODE on stdout: %m");

                break;
        }

        return 0;
}

static int modeset_run(Modeset *m) {
        struct termios in_attr, saved_attr;
        int r;

        assert(m);

        if (!m->my_tty) {
                log_warning("You need to run this program on a free VT");
                return -EACCES;
        }

        if (!m->managed && geteuid() > 0)
                log_warning("You run in unmanaged mode without being root. This is likely to fail..");

        printf("modeset - Show test pattern on selected graphics devices\n"
               "          Running on seat '%s' in user-session '%s'\n"
               "          Exit by pressing ^C\n\n",
               m->seat ? : "seat0", m->session ? : "<none>");

        r = sysview_context_start(m->sysview, modeset_sysview_fn, m);
        if (r < 0)
                goto out;

        r = tcgetattr(0, &in_attr);
        if (r < 0) {
                r = -errno;
                goto out;
        }

        saved_attr = in_attr;
        in_attr.c_lflag &= ~ECHO;

        r = tcsetattr(0, TCSANOW, &in_attr);
        if (r < 0) {
                r = -errno;
                goto out;
        }

        r = sd_event_loop(m->event);
        tcsetattr(0, TCSANOW, &saved_attr);
        printf("exiting..\n");

out:
        sysview_context_stop(m->sysview);
        return r;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Show test pattern on all selected graphics devices.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };
        static const struct option options[] = {
                { "help",       no_argument,    NULL, 'h'               },
                { "version",    no_argument,    NULL, ARG_VERSION       },
                {},
        };
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc > optind) {
                log_error("Too many arguments");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        _cleanup_(modeset_freep) Modeset *m = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        initialize_srand();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = modeset_new(&m);
        if (r < 0)
                goto finish;

        r = modeset_run(m);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
