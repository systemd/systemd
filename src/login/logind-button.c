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
#include "sd-messages.h"

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

                /* If the device has been unplugged close() returns
                 * ENODEV, let's ignore this, hence we don't use
                 * close_nointr_nofail() */
                close(b->fd);
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
                close(b->fd);
                b->fd = -1;
        }

        p = strappend("/dev/input/", b->name);
        if (!p)
                return log_oom();

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
        close(b->fd);
        b->fd = -1;
        return r;
}

static int button_handle(
                Button *b,
                InhibitWhat inhibit_key,
                HandleAction handle,
                bool ignore_inhibited,
                bool is_edge) {

        int r;

        assert(b);

        r = manager_handle_action(b->manager, inhibit_key, handle, ignore_inhibited, is_edge);
        if (r > 0)
                /* We are executing the operation, so make sure we don't
                 * execute another one until the lid is opened/closed again */
                b->lid_close_queued = false;

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
                        log_struct(LOG_INFO,
                                   "MESSAGE=Power key pressed.",
                                   MESSAGE_ID(SD_MESSAGE_POWER_KEY),
                                   NULL);
                        return button_handle(b, INHIBIT_HANDLE_POWER_KEY, b->manager->handle_power_key, b->manager->power_key_ignore_inhibited, true);

                /* The kernel is a bit confused here:

                   KEY_SLEEP   = suspend-to-ram, which everybody else calls "suspend"
                   KEY_SUSPEND = suspend-to-disk, which everybody else calls "hibernate"
                */

                case KEY_SLEEP:
                        log_struct(LOG_INFO,
                                   "MESSAGE=Suspend key pressed.",
                                   MESSAGE_ID(SD_MESSAGE_SUSPEND_KEY),
                                   NULL);
                        return button_handle(b, INHIBIT_HANDLE_SUSPEND_KEY, b->manager->handle_suspend_key, b->manager->suspend_key_ignore_inhibited, true);

                case KEY_SUSPEND:
                        log_struct(LOG_INFO,
                                   "MESSAGE=Hibernate key pressed.",
                                   MESSAGE_ID(SD_MESSAGE_HIBERNATE_KEY),
                                   NULL);
                        return button_handle(b, INHIBIT_HANDLE_HIBERNATE_KEY, b->manager->handle_hibernate_key, b->manager->hibernate_key_ignore_inhibited, true);
                }

        } else if (ev.type == EV_SW && ev.value > 0) {

                switch (ev.code) {

                case SW_LID:
                        log_struct(LOG_INFO,
                                   "MESSAGE=Lid closed.",
                                   MESSAGE_ID(SD_MESSAGE_LID_CLOSED),
                                   NULL);
                        b->lid_close_queued = true;

                        return button_handle(b, INHIBIT_HANDLE_LID_SWITCH, b->manager->handle_lid_switch, b->manager->lid_switch_ignore_inhibited, true);
                }

        } else if (ev.type == EV_SW && ev.value == 0) {

                switch (ev.code) {

                case SW_LID:
                        log_struct(LOG_INFO,
                                   "MESSAGE=Lid opened.",
                                   MESSAGE_ID(SD_MESSAGE_LID_OPENED),
                                   NULL);
                        b->lid_close_queued = false;
                        break;
                }
        }

        return 0;
}

int button_recheck(Button *b) {
        assert(b);

        if (!b->lid_close_queued)
                return 0;

        return button_handle(b, INHIBIT_HANDLE_LID_SWITCH, b->manager->handle_lid_switch, b->manager->lid_switch_ignore_inhibited, false);
}
