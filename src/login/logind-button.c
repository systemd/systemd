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

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/input.h>

#include "sd-messages.h"
#include "util.h"
#include "logind-button.h"

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

        sd_event_source_unref(b->io_event_source);
        sd_event_source_unref(b->check_event_source);

        if (b->fd >= 0) {
                /* If the device has been unplugged close() returns
                 * ENODEV, let's ignore this, hence we don't use
                 * safe_close() */
                (void) close(b->fd);
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

static void button_lid_switch_handle_action(Manager *manager, bool is_edge) {
        HandleAction handle_action;

        assert(manager);

        /* If we are docked, handle the lid switch differently */
        if (manager_is_docked_or_external_displays(manager))
                handle_action = manager->handle_lid_switch_docked;
        else
                handle_action = manager->handle_lid_switch;

        manager_handle_action(manager, INHIBIT_HANDLE_LID_SWITCH, handle_action, manager->lid_switch_ignore_inhibited, is_edge);
}

static int button_recheck(sd_event_source *e, void *userdata) {
        Button *b = userdata;

        assert(b);
        assert(b->lid_closed);

        button_lid_switch_handle_action(b->manager, false);
        return 1;
}

static int button_install_check_event_source(Button *b) {
        int r;
        assert(b);

        /* Install a post handler, so that we keep rechecking as long as the lid is closed. */

        if (b->check_event_source)
                return 0;

        r = sd_event_add_post(b->manager->event, &b->check_event_source, button_recheck, b);
        if (r < 0)
                return r;

        return sd_event_source_set_priority(b->check_event_source, SD_EVENT_PRIORITY_IDLE+1);
}

static int button_dispatch(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Button *b = userdata;
        struct input_event ev;
        ssize_t l;

        assert(s);
        assert(fd == b->fd);
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
                                   LOG_MESSAGE("Power key pressed."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_POWER_KEY),
                                   NULL);

                        manager_handle_action(b->manager, INHIBIT_HANDLE_POWER_KEY, b->manager->handle_power_key, b->manager->power_key_ignore_inhibited, true);
                        break;

                /* The kernel is a bit confused here:

                   KEY_SLEEP   = suspend-to-ram, which everybody else calls "suspend"
                   KEY_SUSPEND = suspend-to-disk, which everybody else calls "hibernate"
                */

                case KEY_SLEEP:
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Suspend key pressed."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_SUSPEND_KEY),
                                   NULL);

                        manager_handle_action(b->manager, INHIBIT_HANDLE_SUSPEND_KEY, b->manager->handle_suspend_key, b->manager->suspend_key_ignore_inhibited, true);
                        break;

                case KEY_SUSPEND:
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Hibernate key pressed."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_HIBERNATE_KEY),
                                   NULL);

                        manager_handle_action(b->manager, INHIBIT_HANDLE_HIBERNATE_KEY, b->manager->handle_hibernate_key, b->manager->hibernate_key_ignore_inhibited, true);
                        break;
                }

        } else if (ev.type == EV_SW && ev.value > 0) {

                if (ev.code == SW_LID) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Lid closed."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_LID_CLOSED),
                                   NULL);

                        b->lid_closed = true;
                        button_lid_switch_handle_action(b->manager, true);
                        button_install_check_event_source(b);

                } else if (ev.code == SW_DOCK) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("System docked."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_SYSTEM_DOCKED),
                                   NULL);

                        b->docked = true;
                }

        } else if (ev.type == EV_SW && ev.value == 0) {

                if (ev.code == SW_LID) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Lid opened."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_LID_OPENED),
                                   NULL);

                        b->lid_closed = false;
                        b->check_event_source = sd_event_source_unref(b->check_event_source);

                } else if (ev.code == SW_DOCK) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("System undocked."),
                                   LOG_MESSAGE_ID(SD_MESSAGE_SYSTEM_UNDOCKED),
                                   NULL);

                        b->docked = false;
                }
        }

        return 0;
}

int button_open(Button *b) {
        char *p, name[256];
        int r;

        assert(b);

        if (b->fd >= 0) {
                close(b->fd);
                b->fd = -1;
        }

        p = strjoina("/dev/input/", b->name);

        b->fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (b->fd < 0)
                return log_warning_errno(errno, "Failed to open %s: %m", b->name);

        if (ioctl(b->fd, EVIOCGNAME(sizeof(name)), name) < 0) {
                log_error_errno(errno, "Failed to get input name: %m");
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(b->manager->event, &b->io_event_source, b->fd, EPOLLIN, button_dispatch, b);
        if (r < 0) {
                log_error_errno(r, "Failed to add button event: %m");
                goto fail;
        }

        log_info("Watching system buttons on /dev/input/%s (%s)", b->name, name);

        return 0;

fail:
        close(b->fd);
        b->fd = -1;
        return r;
}

int button_check_switches(Button *b) {
        uint8_t switches[SW_MAX/8+1] = {};
        assert(b);

        if (b->fd < 0)
                return -EINVAL;

        if (ioctl(b->fd, EVIOCGSW(sizeof(switches)), switches) < 0)
                return -errno;

        b->lid_closed = (switches[SW_LID/8] >> (SW_LID % 8)) & 1;
        b->docked = (switches[SW_DOCK/8] >> (SW_DOCK % 8)) & 1;

        if (b->lid_closed)
                button_install_check_event_source(b);

        return 0;
}
