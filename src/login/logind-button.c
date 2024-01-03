/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "async.h"
#include "fd-util.h"
#include "logind-button.h"
#include "missing_input.h"
#include "string-util.h"

#define CONST_MAX5(a, b, c, d, e) CONST_MAX(CONST_MAX(a, b), CONST_MAX(CONST_MAX(c, d), e))

#define ULONG_BITS (sizeof(unsigned long)*8)

#define LONG_PRESS_DURATION (5 * USEC_PER_SEC)

static bool bitset_get(const unsigned long *bits, unsigned i) {
        return (bits[i / ULONG_BITS] >> (i % ULONG_BITS)) & 1UL;
}

static void bitset_put(unsigned long *bits, unsigned i) {
        bits[i / ULONG_BITS] |= (unsigned long) 1 << (i % ULONG_BITS);
}

Button* button_new(Manager *m, const char *name) {
        Button *b;

        assert(m);
        assert(name);

        b = new0(Button, 1);
        if (!b)
                return NULL;

        b->name = strdup(name);
        if (!b->name)
                return mfree(b);

        if (hashmap_put(m->buttons, b->name, b) < 0) {
                free(b->name);
                return mfree(b);
        }

        b->manager = m;
        b->fd = -EBADF;

        return b;
}

Button *button_free(Button *b) {
        if (!b)
                return NULL;

        hashmap_remove(b->manager->buttons, b->name);

        sd_event_source_unref(b->io_event_source);
        sd_event_source_unref(b->check_event_source);

        asynchronous_close(b->fd);

        free(b->name);
        free(b->seat);

        return mfree(b);
}

int button_set_seat(Button *b, const char *sn) {
        assert(b);

        return free_and_strdup(&b->seat, sn);
}

static void button_lid_switch_handle_action(Manager *manager, bool is_edge) {
        HandleAction handle_action;

        assert(manager);

        /* If we are docked or on external power, handle the lid switch
         * differently */
        if (manager_is_docked_or_external_displays(manager))
                handle_action = manager->handle_lid_switch_docked;
        else if (handle_action_valid(manager->handle_lid_switch_ep) && manager_is_on_external_power())
                handle_action = manager->handle_lid_switch_ep;
        else
                handle_action = manager->handle_lid_switch;

        manager_handle_action(manager, INHIBIT_HANDLE_LID_SWITCH, handle_action, manager->lid_switch_ignore_inhibited, is_edge);
}

static int button_recheck(sd_event_source *e, void *userdata) {
        Button *b = ASSERT_PTR(userdata);

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

static int long_press_of_power_key_handler(sd_event_source *e, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(e);

        m->power_key_long_press_event_source = sd_event_source_unref(m->power_key_long_press_event_source);

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Power key pressed long."),
                   "MESSAGE_ID=" SD_MESSAGE_POWER_KEY_LONG_PRESS_STR);

        manager_handle_action(m, INHIBIT_HANDLE_POWER_KEY, m->handle_power_key_long_press, m->power_key_ignore_inhibited, true);
        return 0;
}

static int long_press_of_reboot_key_handler(sd_event_source *e, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(e);

        m->reboot_key_long_press_event_source = sd_event_source_unref(m->reboot_key_long_press_event_source);

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Reboot key pressed long."),
                   "MESSAGE_ID=" SD_MESSAGE_REBOOT_KEY_LONG_PRESS_STR);

        manager_handle_action(m, INHIBIT_HANDLE_REBOOT_KEY, m->handle_reboot_key_long_press, m->reboot_key_ignore_inhibited, true);
        return 0;
}

static int long_press_of_suspend_key_handler(sd_event_source *e, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(e);

        m->suspend_key_long_press_event_source = sd_event_source_unref(m->suspend_key_long_press_event_source);

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Suspend key pressed long."),
                   "MESSAGE_ID=" SD_MESSAGE_SUSPEND_KEY_LONG_PRESS_STR);

        manager_handle_action(m, INHIBIT_HANDLE_SUSPEND_KEY, m->handle_suspend_key_long_press, m->suspend_key_ignore_inhibited, true);
        return 0;
}

static int long_press_of_hibernate_key_handler(sd_event_source *e, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(e);

        m->hibernate_key_long_press_event_source = sd_event_source_unref(m->hibernate_key_long_press_event_source);

        log_struct(LOG_INFO,
                   LOG_MESSAGE("Hibernate key pressed long."),
                   "MESSAGE_ID=" SD_MESSAGE_HIBERNATE_KEY_LONG_PRESS_STR);

        manager_handle_action(m, INHIBIT_HANDLE_HIBERNATE_KEY, m->handle_hibernate_key_long_press, m->hibernate_key_ignore_inhibited, true);
        return 0;
}

static void start_long_press(Manager *m, sd_event_source **e, sd_event_time_handler_t callback) {
        int r;

        assert(m);
        assert(e);

        if (*e)
                return;

        r = sd_event_add_time_relative(
                        m->event,
                        e,
                        CLOCK_MONOTONIC,
                        LONG_PRESS_DURATION, 0,
                        callback, m);
        if (r < 0)
                log_warning_errno(r, "Failed to add long press timer event, ignoring: %m");
}

static int button_dispatch(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Button *b = ASSERT_PTR(userdata);
        struct input_event ev;
        ssize_t l;

        assert(s);
        assert(fd == b->fd);

        l = read(b->fd, &ev, sizeof(ev));
        if (l < 0)
                return errno != EAGAIN ? -errno : 0;
        if ((size_t) l < sizeof(ev))
                return -EIO;

        if (ev.type == EV_KEY && ev.value > 0) {

                switch (ev.code) {

                case KEY_POWER:
                case KEY_POWER2:
                        if (b->manager->handle_power_key_long_press != HANDLE_IGNORE && b->manager->handle_power_key_long_press != b->manager->handle_power_key) {
                                log_debug("Power key pressed. Further action depends on the key press duration.");
                                start_long_press(b->manager, &b->manager->power_key_long_press_event_source, long_press_of_power_key_handler);
                        } else {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Power key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_POWER_KEY_STR);
                                manager_handle_action(b->manager, INHIBIT_HANDLE_POWER_KEY, b->manager->handle_power_key, b->manager->power_key_ignore_inhibited, true);
                        }
                        break;

                /* The kernel naming is a bit confusing here:
                   KEY_RESTART was probably introduced for media playback purposes, but
                   is now being predominantly used to indicate device reboot.
                */

                case KEY_RESTART:
                        if (b->manager->handle_reboot_key_long_press != HANDLE_IGNORE && b->manager->handle_reboot_key_long_press != b->manager->handle_reboot_key) {
                                log_debug("Reboot key pressed. Further action depends on the key press duration.");
                                start_long_press(b->manager, &b->manager->reboot_key_long_press_event_source, long_press_of_reboot_key_handler);
                        } else {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Reboot key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_REBOOT_KEY_STR);
                                manager_handle_action(b->manager, INHIBIT_HANDLE_REBOOT_KEY, b->manager->handle_reboot_key, b->manager->reboot_key_ignore_inhibited, true);
                        }
                        break;

                /* The kernel naming is a bit confusing here:

                   KEY_SLEEP   = suspend-to-ram, which everybody else calls "suspend"
                   KEY_SUSPEND = suspend-to-disk, which everybody else calls "hibernate"
                */

                case KEY_SLEEP:
                        if (b->manager->handle_suspend_key_long_press != HANDLE_IGNORE && b->manager->handle_suspend_key_long_press != b->manager->handle_suspend_key) {
                                log_debug("Suspend key pressed. Further action depends on the key press duration.");
                                start_long_press(b->manager, &b->manager->suspend_key_long_press_event_source, long_press_of_suspend_key_handler);
                        } else {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Suspend key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_SUSPEND_KEY_STR);
                                manager_handle_action(b->manager, INHIBIT_HANDLE_SUSPEND_KEY, b->manager->handle_suspend_key, b->manager->suspend_key_ignore_inhibited, true);
                        }
                        break;

                case KEY_SUSPEND:
                        if (b->manager->handle_hibernate_key_long_press != HANDLE_IGNORE && b->manager->handle_hibernate_key_long_press != b->manager->handle_hibernate_key) {
                                log_debug("Hibernate key pressed. Further action depends on the key press duration.");
                                start_long_press(b->manager, &b->manager->hibernate_key_long_press_event_source, long_press_of_hibernate_key_handler);
                        } else {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Hibernate key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_HIBERNATE_KEY_STR);
                                manager_handle_action(b->manager, INHIBIT_HANDLE_HIBERNATE_KEY, b->manager->handle_hibernate_key, b->manager->hibernate_key_ignore_inhibited, true);
                        }
                        break;
                }

        } else if (ev.type == EV_KEY && ev.value == 0) {

                switch (ev.code) {

                case KEY_POWER:
                case KEY_POWER2:
                        if (b->manager->power_key_long_press_event_source) {
                                /* Long press event timer is still pending and key release
                                   event happened.  This means that key press duration was
                                   insufficient to trigger a long press event
                                */
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Power key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_POWER_KEY_STR);

                                b->manager->power_key_long_press_event_source = sd_event_source_unref(b->manager->power_key_long_press_event_source);

                                manager_handle_action(b->manager, INHIBIT_HANDLE_POWER_KEY, b->manager->handle_power_key, b->manager->power_key_ignore_inhibited, true);
                        }
                        break;

                case KEY_RESTART:
                        if (b->manager->reboot_key_long_press_event_source) {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Reboot key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_REBOOT_KEY_STR);

                                b->manager->reboot_key_long_press_event_source = sd_event_source_unref(b->manager->reboot_key_long_press_event_source);

                                manager_handle_action(b->manager, INHIBIT_HANDLE_REBOOT_KEY, b->manager->handle_reboot_key, b->manager->reboot_key_ignore_inhibited, true);
                        }
                        break;

                case KEY_SLEEP:
                        if (b->manager->suspend_key_long_press_event_source) {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Suspend key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_SUSPEND_KEY_STR);

                                b->manager->suspend_key_long_press_event_source = sd_event_source_unref(b->manager->suspend_key_long_press_event_source);

                                manager_handle_action(b->manager, INHIBIT_HANDLE_SUSPEND_KEY, b->manager->handle_suspend_key, b->manager->suspend_key_ignore_inhibited, true);
                        }
                        break;
                case KEY_SUSPEND:
                        if (b->manager->hibernate_key_long_press_event_source) {
                                log_struct(LOG_INFO,
                                           LOG_MESSAGE("Hibernate key pressed short."),
                                           "MESSAGE_ID=" SD_MESSAGE_HIBERNATE_KEY_STR);

                                b->manager->hibernate_key_long_press_event_source = sd_event_source_unref(b->manager->hibernate_key_long_press_event_source);

                                manager_handle_action(b->manager, INHIBIT_HANDLE_HIBERNATE_KEY, b->manager->handle_hibernate_key, b->manager->hibernate_key_ignore_inhibited, true);
                        }
                        break;
                }

        } else if (ev.type == EV_SW && ev.value > 0) {

                if (ev.code == SW_LID) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Lid closed."),
                                   "MESSAGE_ID=" SD_MESSAGE_LID_CLOSED_STR);

                        b->lid_closed = true;
                        button_lid_switch_handle_action(b->manager, true);
                        button_install_check_event_source(b);
                        manager_send_changed(b->manager, "LidClosed", NULL);
                } else if (ev.code == SW_DOCK) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("System docked."),
                                   "MESSAGE_ID=" SD_MESSAGE_SYSTEM_DOCKED_STR);

                        b->docked = true;
                        manager_send_changed(b->manager, "Docked", NULL);
                }

        } else if (ev.type == EV_SW && ev.value == 0) {

                if (ev.code == SW_LID) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("Lid opened."),
                                   "MESSAGE_ID=" SD_MESSAGE_LID_OPENED_STR);

                        b->lid_closed = false;
                        b->check_event_source = sd_event_source_unref(b->check_event_source);
                        manager_send_changed(b->manager, "LidClosed", NULL);

                } else if (ev.code == SW_DOCK) {
                        log_struct(LOG_INFO,
                                   LOG_MESSAGE("System undocked."),
                                   "MESSAGE_ID=" SD_MESSAGE_SYSTEM_UNDOCKED_STR);

                        b->docked = false;
                        manager_send_changed(b->manager, "Docked", NULL);
                }
        }

        return 0;
}

static int button_suitable(int fd) {
        unsigned long types[CONST_MAX(EV_KEY, EV_SW)/ULONG_BITS+1];

        assert(fd >= 0);

        if (ioctl(fd, EVIOCGBIT(EV_SYN, sizeof types), types) < 0)
                return -errno;

        if (bitset_get(types, EV_KEY)) {
                unsigned long keys[CONST_MAX5(KEY_POWER, KEY_POWER2, KEY_SLEEP, KEY_SUSPEND, KEY_RESTART)/ULONG_BITS+1];

                if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof keys), keys) < 0)
                        return -errno;

                if (bitset_get(keys, KEY_POWER) ||
                    bitset_get(keys, KEY_POWER2) ||
                    bitset_get(keys, KEY_SLEEP) ||
                    bitset_get(keys, KEY_SUSPEND) ||
                    bitset_get(keys, KEY_RESTART))
                        return true;
        }

        if (bitset_get(types, EV_SW)) {
                unsigned long switches[CONST_MAX(SW_LID, SW_DOCK)/ULONG_BITS+1];

                if (ioctl(fd, EVIOCGBIT(EV_SW, sizeof switches), switches) < 0)
                        return -errno;

                if (bitset_get(switches, SW_LID) ||
                    bitset_get(switches, SW_DOCK))
                        return true;
        }

        return false;
}

static int button_set_mask(const char *name, int fd) {
        unsigned long
                types[CONST_MAX(EV_KEY, EV_SW)/ULONG_BITS+1] = {},
                keys[CONST_MAX5(KEY_POWER, KEY_POWER2, KEY_SLEEP, KEY_SUSPEND, KEY_RESTART)/ULONG_BITS+1] = {},
                switches[CONST_MAX(SW_LID, SW_DOCK)/ULONG_BITS+1] = {};
        struct input_mask mask;

        assert(name);
        assert(fd >= 0);

        bitset_put(types, EV_KEY);
        bitset_put(types, EV_SW);

        mask = (struct input_mask) {
                .type = EV_SYN,
                .codes_size = sizeof(types),
                .codes_ptr = PTR_TO_UINT64(types),
        };

        if (ioctl(fd, EVIOCSMASK, &mask) < 0)
                /* Log only at debug level if the kernel doesn't do EVIOCSMASK yet */
                return log_full_errno(IN_SET(errno, ENOTTY, EOPNOTSUPP, EINVAL) ? LOG_DEBUG : LOG_WARNING,
                                      errno, "Failed to set EV_SYN event mask on /dev/input/%s: %m", name);

        bitset_put(keys, KEY_POWER);
        bitset_put(keys, KEY_POWER2);
        bitset_put(keys, KEY_SLEEP);
        bitset_put(keys, KEY_SUSPEND);
        bitset_put(keys, KEY_RESTART);

        mask = (struct input_mask) {
                .type = EV_KEY,
                .codes_size = sizeof(keys),
                .codes_ptr = PTR_TO_UINT64(keys),
        };

        if (ioctl(fd, EVIOCSMASK, &mask) < 0)
                return log_warning_errno(errno, "Failed to set EV_KEY event mask on /dev/input/%s: %m", name);

        bitset_put(switches, SW_LID);
        bitset_put(switches, SW_DOCK);

        mask = (struct input_mask) {
                .type = EV_SW,
                .codes_size = sizeof(switches),
                .codes_ptr = PTR_TO_UINT64(switches),
        };

        if (ioctl(fd, EVIOCSMASK, &mask) < 0)
                return log_warning_errno(errno, "Failed to set EV_SW event mask on /dev/input/%s: %m", name);

        return 0;
}

int button_open(Button *b) {
        _cleanup_(asynchronous_closep) int fd = -EBADF;
        const char *p;
        char name[256];
        int r;

        assert(b);

        b->fd = asynchronous_close(b->fd);

        p = strjoina("/dev/input/", b->name);

        fd = open(p, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (fd < 0)
                return log_warning_errno(errno, "Failed to open %s: %m", p);

        r = button_suitable(fd);
        if (r < 0)
                return log_warning_errno(r, "Failed to determine whether input device %s is relevant to us: %m", p);
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                       "Device %s does not expose keys or switches relevant to us, ignoring.", p);

        if (ioctl(fd, EVIOCGNAME(sizeof name), name) < 0)
                return log_error_errno(errno, "Failed to get input name for %s: %m", p);

        (void) button_set_mask(b->name, fd);

        b->io_event_source = sd_event_source_unref(b->io_event_source);
        r = sd_event_add_io(b->manager->event, &b->io_event_source, fd, EPOLLIN, button_dispatch, b);
        if (r < 0)
                return log_error_errno(r, "Failed to add button event for %s: %m", p);

        b->fd = TAKE_FD(fd);
        log_info("Watching system buttons on %s (%s)", p, name);
        return 0;
}

int button_check_switches(Button *b) {
        unsigned long switches[CONST_MAX(SW_LID, SW_DOCK)/ULONG_BITS+1] = {};
        assert(b);

        if (b->fd < 0)
                return -EINVAL;

        if (ioctl(b->fd, EVIOCGSW(sizeof(switches)), switches) < 0)
                return -errno;

        b->lid_closed = bitset_get(switches, SW_LID);
        b->docked = bitset_get(switches, SW_DOCK);
        manager_send_changed(b->manager, "Docked", "LidClosed", NULL);

        if (b->lid_closed)
                button_install_check_event_source(b);

        return 0;
}
