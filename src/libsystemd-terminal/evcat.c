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
 * Event Catenation
 * The evcat tool catenates input events of all requested devices and prints
 * them to standard-output. It's only meant for debugging of input-related
 * problems.
 */

#include <errno.h>
#include <getopt.h>
#include <libevdev/libevdev.h>
#include <linux/kd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <xkbcommon/xkbcommon.h>
#include "sd-bus.h"
#include "sd-event.h"
#include "sd-login.h"
#include "build.h"
#include "event-util.h"
#include "macro.h"
#include "signal-util.h"
#include "util.h"
#include "idev.h"
#include "sysview.h"
#include "term-internal.h"

typedef struct Evcat Evcat;

struct Evcat {
        char *session;
        char *seat;
        sd_event *event;
        sd_bus *bus;
        sysview_context *sysview;
        idev_context *idev;
        idev_session *idev_session;

        bool managed : 1;
};

static Evcat *evcat_free(Evcat *e) {
        if (!e)
                return NULL;

        e->idev_session = idev_session_free(e->idev_session);
        e->idev = idev_context_unref(e->idev);
        e->sysview = sysview_context_free(e->sysview);
        e->bus = sd_bus_unref(e->bus);
        e->event = sd_event_unref(e->event);
        free(e->seat);
        free(e->session);
        free(e);

        tcflush(0, TCIOFLUSH);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Evcat*, evcat_free);

static bool is_managed(const char *session) {
        unsigned int vtnr;
        struct stat st;
        long mode;
        int r;

        /* Using logind's Controller API is highly fragile if there is already
         * a session controller running. If it is registered as controller
         * itself, TakeControl will simply fail. But if its a legacy controller
         * that does not use logind's controller API, we must never register
         * our own controller. Otherwise, we really mess up the VT. Therefore,
         * only run in managed mode if there's no-one else. */

        if (geteuid() == 0)
                return false;

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

static int evcat_new(Evcat **out) {
        _cleanup_(evcat_freep) Evcat *e = NULL;
        int r;

        assert(out);

        e = new0(Evcat, 1);
        if (!e)
                return log_oom();

        r = sd_pid_get_session(getpid(), &e->session);
        if (r < 0)
                return log_error_errno(r, "Cannot retrieve logind session: %m");

        r = sd_session_get_seat(e->session, &e->seat);
        if (r < 0)
                return log_error_errno(r, "Cannot retrieve seat of logind session: %m");

        e->managed = is_managed(e->session);

        r = sd_event_default(&e->event);
        if (r < 0)
                return r;

        r = sd_bus_open_system(&e->bus);
        if (r < 0)
                return r;

        r = sd_bus_attach_event(e->bus, e->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        r = sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1);
        if (r < 0)
                return r;

        r = sd_event_add_signal(e->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(e->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sysview_context_new(&e->sysview,
                                SYSVIEW_CONTEXT_SCAN_LOGIND |
                                SYSVIEW_CONTEXT_SCAN_EVDEV,
                                e->event,
                                e->bus,
                                NULL);
        if (r < 0)
                return r;

        r = idev_context_new(&e->idev, e->event, e->bus);
        if (r < 0)
                return r;

        *out = e;
        e = NULL;
        return 0;
}

static void kdata_print(idev_data *data) {
        idev_data_keyboard *k = &data->keyboard;
        char buf[128];
        uint32_t i, c;
        int cwidth;

        /* Key-press state: UP/DOWN/REPEAT */
        printf(" %-6s", k->value == 0 ? "UP" :
                        k->value == 1 ? "DOWN" :
                        "REPEAT");

        /* Resync state */
        printf(" | %-6s", data->resync ? "RESYNC" : "");

        /* Keycode that triggered the event */
        printf(" | %5u", (unsigned)k->keycode);

        /* Well-known name of the keycode */
        printf(" | %-20s", libevdev_event_code_get_name(EV_KEY, k->keycode) ? : "<unknown>");

        /* Well-known modifiers */
        printf(" | %-5s", (k->mods & IDEV_KBDMOD_SHIFT) ? "SHIFT" : "");
        printf(" %-4s", (k->mods & IDEV_KBDMOD_CTRL) ? "CTRL" : "");
        printf(" %-3s", (k->mods & IDEV_KBDMOD_ALT) ? "ALT" : "");
        printf(" %-5s", (k->mods & IDEV_KBDMOD_LINUX) ? "LINUX" : "");
        printf(" %-4s", (k->mods & IDEV_KBDMOD_CAPS) ? "CAPS" : "");

        /* Consumed modifiers */
        printf(" | %-5s", (k->consumed_mods & IDEV_KBDMOD_SHIFT) ? "SHIFT" : "");
        printf(" %-4s", (k->consumed_mods & IDEV_KBDMOD_CTRL) ? "CTRL" : "");
        printf(" %-3s", (k->consumed_mods & IDEV_KBDMOD_ALT) ? "ALT" : "");
        printf(" %-5s", (k->consumed_mods & IDEV_KBDMOD_LINUX) ? "LINUX" : "");
        printf(" %-4s", (k->consumed_mods & IDEV_KBDMOD_CAPS) ? "CAPS" : "");

        /* Resolved symbols */
        printf(" |");
        for (i = 0; i < k->n_syms; ++i) {
                buf[0] = 0;
                xkb_keysym_get_name(k->keysyms[i], buf, sizeof(buf));

                if (is_locale_utf8()) {
                        c = k->codepoints[i];
                        if (c < 0x110000 && c > 0x20 && (c < 0x7f || c > 0x9f)) {
                                /* "%4lc" doesn't work well, so hard-code it */
                                cwidth = mk_wcwidth(c);
                                while (cwidth++ < 2)
                                        printf(" ");

                                printf(" '%lc':", (wchar_t)c);
                        } else {
                                printf("      ");
                        }
                }

                printf(" XKB_KEY_%-30s", buf);
        }

        printf("\n");
}

static bool kdata_is_exit(idev_data *data) {
        idev_data_keyboard *k = &data->keyboard;

        if (k->value != 1)
                return false;
        if (k->n_syms != 1)
                return false;

        return k->codepoints[0] == 'q';
}

static int evcat_idev_fn(idev_session *session, void *userdata, idev_event *ev) {
        Evcat *e = userdata;

        switch (ev->type) {
        case IDEV_EVENT_DEVICE_ADD:
                idev_device_enable(ev->device_add.device);
                break;
        case IDEV_EVENT_DEVICE_REMOVE:
                idev_device_disable(ev->device_remove.device);
                break;
        case IDEV_EVENT_DEVICE_DATA:
                switch (ev->device_data.data.type) {
                case IDEV_DATA_KEYBOARD:
                        if (kdata_is_exit(&ev->device_data.data))
                                sd_event_exit(e->event, 0);
                        else
                                kdata_print(&ev->device_data.data);

                        break;
                }

                break;
        }

        return 0;
}

static int evcat_sysview_fn(sysview_context *c, void *userdata, sysview_event *ev) {
        unsigned int flags, type;
        Evcat *e = userdata;
        sysview_device *d;
        const char *name;
        int r;

        switch (ev->type) {
        case SYSVIEW_EVENT_SESSION_FILTER:
                if (streq_ptr(e->session, ev->session_filter.id))
                        return 1;

                break;
        case SYSVIEW_EVENT_SESSION_ADD:
                assert(!e->idev_session);

                name = sysview_session_get_name(ev->session_add.session);
                flags = 0;

                if (e->managed)
                        flags |= IDEV_SESSION_MANAGED;

                r = idev_session_new(&e->idev_session,
                                     e->idev,
                                     flags,
                                     name,
                                     evcat_idev_fn,
                                     e);
                if (r < 0)
                        return log_error_errno(r, "Cannot create idev session: %m");

                if (e->managed) {
                        r = sysview_session_take_control(ev->session_add.session);
                        if (r < 0)
                                return log_error_errno(r, "Cannot request session control: %m");
                }

                idev_session_enable(e->idev_session);

                break;
        case SYSVIEW_EVENT_SESSION_REMOVE:
                idev_session_disable(e->idev_session);
                e->idev_session = idev_session_free(e->idev_session);
                if (sd_event_get_exit_code(e->event, &r) == -ENODATA)
                        sd_event_exit(e->event, 0);
                break;
        case SYSVIEW_EVENT_SESSION_ATTACH:
                d = ev->session_attach.device;
                type = sysview_device_get_type(d);
                if (type == SYSVIEW_DEVICE_EVDEV) {
                        r = idev_session_add_evdev(e->idev_session, sysview_device_get_ud(d));
                        if (r < 0)
                                return log_error_errno(r, "Cannot add evdev device to idev: %m");
                }

                break;
        case SYSVIEW_EVENT_SESSION_DETACH:
                d = ev->session_detach.device;
                type = sysview_device_get_type(d);
                if (type == SYSVIEW_DEVICE_EVDEV) {
                        r = idev_session_remove_evdev(e->idev_session, sysview_device_get_ud(d));
                        if (r < 0)
                                return log_error_errno(r, "Cannot remove evdev device from idev: %m");
                }

                break;
        case SYSVIEW_EVENT_SESSION_CONTROL:
                r = ev->session_control.error;
                if (r < 0)
                        return log_error_errno(r, "Cannot acquire session control: %m");

                r = ioctl(1, KDSKBMODE, K_UNICODE);
                if (r < 0)
                        return log_error_errno(errno, "Cannot set K_UNICODE on stdout: %m");

                r = ioctl(1, KDSETMODE, KD_TEXT);
                if (r < 0)
                        return log_error_errno(errno, "Cannot set KD_TEXT on stdout: %m");

                printf("\n");

                break;
        }

        return 0;
}

static int evcat_run(Evcat *e) {
        struct termios in_attr, saved_attr;
        int r;

        assert(e);

        if (!e->managed && geteuid() > 0)
                log_warning("You run in unmanaged mode without being root. This is likely to produce no output..");

        printf("evcat - Read and catenate events from selected input devices\n"
               "        Running on seat '%s' in user-session '%s'\n"
               "        Exit by pressing ^C or 'q'\n\n",
               e->seat ? : "seat0", e->session ? : "<none>");

        r = sysview_context_start(e->sysview, evcat_sysview_fn, e);
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

        r = sd_event_loop(e->event);
        tcsetattr(0, TCSANOW, &saved_attr);
        printf("exiting..\n");

out:
        sysview_context_stop(e->sysview);
        return r;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Read and catenate events from selected input devices.\n\n"
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
        _cleanup_(evcat_freep) Evcat *e = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        setlocale(LC_ALL, "");
        if (!is_locale_utf8())
                log_warning("Locale is not set to UTF-8. Codepoints will not be printed!");

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = evcat_new(&e);
        if (r < 0)
                goto finish;

        r = evcat_run(e);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
