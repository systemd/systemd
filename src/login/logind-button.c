/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/epoll.h>

#include "conf-parser.h"
#include "util.h"
#include "logind-button.h"
#include "special.h"
#include "dbus-common.h"

Button* button_new(Manager *m, const char *name) {
        Button *b;

        assert(m);
        assert(name);

        b = new0(Button, 1);
        if (!b)
                return NULL;

        b->name = strdup(name);
        if (!b->name) {
                free(b);
                return NULL;
        }

        if (hashmap_put(m->buttons, b->name, b) < 0) {
                free(b->name);
                free(b);
                return NULL;
        }

        b->manager = m;
        b->fd = -1;

        return b;
}

void button_free(Button *b) {
        assert(b);

        hashmap_remove(b->manager->buttons, b->name);

        if (b->fd >= 0) {
                hashmap_remove(b->manager->button_fds, INT_TO_PTR(b->fd + 1));
                assert_se(epoll_ctl(b->manager->epoll_fd, EPOLL_CTL_DEL, b->fd, NULL) == 0);
                close_nointr_nofail(b->fd);
        }

        free(b->name);
        free(b->seat);
        free(b);
}

int button_set_seat(Button *b, const char *sn) {
        char *s;

        assert(b);
        assert(sn);

        s = strdup(sn);
        if (!s)
                return -ENOMEM;

        free(b->seat);
        b->seat = s;

        return 0;
}

int button_open(Button *b) {
        char name[256], *p;
        struct epoll_event ev;
        int r;

        assert(b);

        if (b->fd >= 0) {
                close_nointr_nofail(b->fd);
                b->fd = -1;
        }

        p = strappend("/dev/input/", b->name);
        if (!p) {
                log_error("Out of memory");
                return -ENOMEM;
        }

        b->fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        free(p);
        if (b->fd < 0) {
                log_warning("Failed to open %s: %m", b->name);
                return -errno;
        }

        if (ioctl(b->fd, EVIOCGNAME(sizeof(name)), name) < 0) {
                log_error("Failed to get input name: %m");
                r = -errno;
                goto fail;
        }

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.u32 = FD_OTHER_BASE + b->fd;

        if (epoll_ctl(b->manager->epoll_fd, EPOLL_CTL_ADD, b->fd, &ev) < 0) {
                log_error("Failed to add to epoll: %m");
                r = -errno;
                goto fail;
        }

        r = hashmap_put(b->manager->button_fds, INT_TO_PTR(b->fd + 1), b);
        if (r < 0) {
                log_error("Failed to add to hash map: %s", strerror(-r));
                assert_se(epoll_ctl(b->manager->epoll_fd, EPOLL_CTL_DEL, b->fd, NULL) == 0);
                goto fail;
        }

        log_info("Watching system buttons on /dev/input/%s (%s)", b->name, name);

        return 0;

fail:
        close_nointr_nofail(b->fd);
        b->fd = -1;
        return r;
}

static Session *button_get_session(Button *b) {
        Seat *seat;
        assert(b);

        if (!b->seat)
                return NULL;

        seat = hashmap_get(b->manager->seats, b->seat);
        if (!seat)
                return NULL;

        return seat->active;
}

static int button_power_off(Button *b, HandleButton handle) {
        DBusError error;
        int r;

        assert(b);

        if (handle == HANDLE_OFF)
                return 0;

        if (handle == HANDLE_NO_SESSION) {
                if (hashmap_size(b->manager->sessions) > 0) {
                        log_error("Refusing power-off, user is logged in.");
                        warn_melody();
                        return -EPERM;
                }

        } else if (handle == HANDLE_TTY_SESSION ||
                   handle == HANDLE_ANY_SESSION) {
                unsigned n;
                Session *s;

                n = hashmap_size(b->manager->sessions);
                s = button_get_session(b);

                /* Silently ignore events of graphical sessions */
                if (handle == HANDLE_TTY_SESSION &&
                    s && s->type == SESSION_X11)
                        return 0;

                if (n > 1 || (n == 1 && !s)) {
                        log_error("Refusing power-off, other user is logged in.");
                        warn_melody();
                        return -EPERM;
                }

        }

        if (handle != HANDLE_ALWAYS) {
                if (manager_is_inhibited(b->manager, INHIBIT_SHUTDOWN, INHIBIT_BLOCK, NULL)) {
                        log_error("Refusing power-off, shutdown is inhibited.");
                        warn_melody();
                        return -EPERM;
                }
        }

        log_info("Powering off...");

        dbus_error_init(&error);
        r = bus_manager_shutdown_or_sleep_now_or_later(b->manager, SPECIAL_POWEROFF_TARGET, INHIBIT_SHUTDOWN, &error);
        if (r < 0) {
                log_error("Failed to power off: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        return r;
}

static int button_suspend(Button *b, HandleButton handle) {
        DBusError error;
        int r;

        assert(b);

        if (handle == HANDLE_OFF)
                return 0;

        if (handle == HANDLE_NO_SESSION) {
                if (hashmap_size(b->manager->sessions) > 0) {
                        log_error("Refusing suspend, user is logged in.");
                        warn_melody();
                        return -EPERM;
                }

        } else if (handle == HANDLE_TTY_SESSION ||
                   handle == HANDLE_ANY_SESSION) {
                unsigned n;
                Session *s;

                n = hashmap_size(b->manager->sessions);
                s = button_get_session(b);

                /* Silently ignore events of graphical sessions */
                if (handle == HANDLE_TTY_SESSION &&
                    s && s->type == SESSION_X11)
                        return 0;

                if (n > 1 || (n == 1 && !s)) {
                        log_error("Refusing suspend, other user is logged in.");
                        warn_melody();
                        return -EPERM;
                }
        }

        if (handle != HANDLE_ALWAYS) {
                if (manager_is_inhibited(b->manager, INHIBIT_SLEEP, INHIBIT_BLOCK, NULL)) {
                        log_error("Refusing suspend, sleeping is inhibited.");
                        warn_melody();
                        return -EPERM;
                }
        }

        log_info("Suspending...");

        dbus_error_init(&error);
        r = bus_manager_shutdown_or_sleep_now_or_later(b->manager, SPECIAL_SUSPEND_TARGET, INHIBIT_SLEEP, &error);
        if (r < 0) {
                log_error("Failed to suspend: %s", bus_error_message(&error));
                dbus_error_free(&error);
        }

        return r;
}

int button_process(Button *b) {
        struct input_event ev;
        ssize_t l;

        assert(b);

        l = read(b->fd, &ev, sizeof(ev));
        if (l < 0)
                return errno != EAGAIN ? -errno : 0;
        if ((size_t) l < sizeof(ev))
                return -EIO;

        if (ev.type == EV_KEY && ev.value > 0) {

                switch (ev.code) {

                case KEY_POWER:
                case KEY_POWER2:
                        log_info("Power key pressed.");
                        return button_power_off(b, b->manager->handle_power_key);

                case KEY_SLEEP:
                case KEY_SUSPEND:
                        log_info("Sleep key pressed.");
                        return button_suspend(b, b->manager->handle_sleep_key);

                }
        } else if (ev.type == EV_SW && ev.value > 0) {

                switch (ev.code) {

                case SW_LID:
                        log_info("Lid closed.");
                        return button_suspend(b, b->manager->handle_lid_switch);
                }
        }

        return 0;
}

static const char* const handle_button_table[_HANDLE_BUTTON_MAX] = {
        [HANDLE_OFF] = "off",
        [HANDLE_NO_SESSION] = "no-session",
        [HANDLE_TTY_SESSION] = "tty-session",
        [HANDLE_ANY_SESSION] = "any-session",
        [HANDLE_ALWAYS] = "always"
};
DEFINE_STRING_TABLE_LOOKUP(handle_button, HandleButton);
DEFINE_CONFIG_PARSE_ENUM(config_parse_handle_button, handle_button, HandleButton, "Failed to parse handle button setting");
