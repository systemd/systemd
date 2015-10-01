/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <linux/rfkill.h>
#include <poll.h>

#include "libudev.h"
#include "sd-daemon.h"

#include "fileio.h"
#include "mkdir.h"
#include "udev-util.h"
#include "util.h"

#define EXIT_USEC (5 * USEC_PER_SEC)

static const char* const rfkill_type_table[NUM_RFKILL_TYPES] = {
        [RFKILL_TYPE_ALL] = "all",
        [RFKILL_TYPE_WLAN] = "wlan",
        [RFKILL_TYPE_BLUETOOTH] = "bluetooth",
        [RFKILL_TYPE_UWB] = "uwb",
        [RFKILL_TYPE_WIMAX] = "wimax",
        [RFKILL_TYPE_WWAN] = "wwan",
        [RFKILL_TYPE_GPS] = "gps",
        [RFKILL_TYPE_FM] "fm",
        [RFKILL_TYPE_NFC] "nfc",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(rfkill_type, int);

static int find_device(
                struct udev *udev,
                const struct rfkill_event *event,
                struct udev_device **ret) {

        _cleanup_free_ char *sysname = NULL;
        struct udev_device *device;
        const char *name;

        assert(udev);
        assert(event);
        assert(ret);

        if (asprintf(&sysname, "rfkill%i", event->idx) < 0)
                return log_oom();

        device = udev_device_new_from_subsystem_sysname(udev, "rfkill", sysname);
        if (!device)
                return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno, "Failed to open device: %m");

        name = udev_device_get_sysattr_value(device, "name");
        if (!name) {
                log_debug("Device has no name, ignoring.");
                udev_device_unref(device);
                return -ENOENT;
        }

        log_debug("Operating on rfkill device '%s'.", name);

        *ret = device;
        return 0;
}

static int wait_for_initialized(
                struct udev *udev,
                struct udev_device *device,
                struct udev_device **ret) {

        _cleanup_udev_monitor_unref_ struct udev_monitor *monitor = NULL;
        struct udev_device *d;
        const char *sysname;
        int watch_fd, r;

        assert(udev);
        assert(device);
        assert(ret);

        if (udev_device_get_is_initialized(device) != 0) {
                *ret = udev_device_ref(device);
                return 0;
        }

        assert_se(sysname = udev_device_get_sysname(device));

        /* Wait until the device is initialized, so that we can get
         * access to the ID_PATH property */

        monitor = udev_monitor_new_from_netlink(udev, "udev");
        if (!monitor)
                return log_error_errno(errno, "Failed to acquire monitor: %m");

        r = udev_monitor_filter_add_match_subsystem_devtype(monitor, "rfkill", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add rfkill udev match to monitor: %m");

        r = udev_monitor_enable_receiving(monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to enable udev receiving: %m");

        watch_fd = udev_monitor_get_fd(monitor);
        if (watch_fd < 0)
                return log_error_errno(watch_fd, "Failed to get watch fd: %m");

        /* Check again, maybe things changed */
        d = udev_device_new_from_subsystem_sysname(udev, "rfkill", sysname);
        if (!d)
                return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno, "Failed to open device: %m");

        if (udev_device_get_is_initialized(d) != 0) {
                *ret = d;
                return 0;
        }

        for (;;) {
                _cleanup_udev_device_unref_ struct udev_device *t = NULL;

                r = fd_wait_for_event(watch_fd, POLLIN, USEC_INFINITY);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to watch udev monitor: %m");

                t = udev_monitor_receive_device(monitor);
                if (!t)
                        continue;

                if (streq_ptr(udev_device_get_sysname(device), sysname)) {
                        *ret = udev_device_ref(t);
                        return 0;
                }
        }
}

static int determine_state_file(
                struct udev *udev,
                const struct rfkill_event *event,
                struct udev_device *d,
                char **ret) {

        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        const char *path_id, *type;
        char *state_file;
        int r;

        assert(event);
        assert(d);
        assert(ret);

        r = wait_for_initialized(udev, d, &device);
        if (r < 0)
                return r;

        assert_se(type = rfkill_type_to_string(event->type));

        path_id = udev_device_get_property_value(device, "ID_PATH");
        if (path_id) {
                _cleanup_free_ char *escaped_path_id = NULL;

                escaped_path_id = cescape(path_id);
                if (!escaped_path_id)
                        return log_oom();

                state_file = strjoin("/var/lib/systemd/rfkill/", escaped_path_id, ":", type, NULL);
        } else
                state_file = strjoin("/var/lib/systemd/rfkill/", type, NULL);

        if (!state_file)
                return log_oom();

        *ret = state_file;
        return 0;
}

static int load_state(
                int rfkill_fd,
                struct udev *udev,
                const struct rfkill_event *event) {

        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        _cleanup_free_ char *state_file = NULL, *value = NULL;
        struct rfkill_event we;
        ssize_t l;
        int b, r;

        assert(rfkill_fd >= 0);
        assert(udev);
        assert(event);

        if (!shall_restore_state())
                return 0;

        r = find_device(udev, event, &device);
        if (r < 0)
                return r;

        r = determine_state_file(udev, event, device, &state_file);
        if (r < 0)
                return r;

        r = read_one_line_file(state_file, &value);
        if (r == -ENOENT) {
                /* No state file? Then save the current state */

                r = write_string_file(state_file, one_zero(event->soft), WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        return log_error_errno(r, "Failed to write state file %s: %m", state_file);

                log_debug("Saved state '%s' to %s.", one_zero(event->soft), state_file);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read state file %s: %m", state_file);

        b = parse_boolean(value);
        if (b < 0)
                return log_error_errno(b, "Failed to parse state file %s: %m", state_file);

        we = (struct rfkill_event) {
                .op = RFKILL_OP_CHANGE,
                .idx = event->idx,
                .soft = b,
        };

        l = write(rfkill_fd, &we, sizeof(we));
        if (l < 0)
                return log_error_errno(errno, "Failed to restore rfkill state for %i: %m", event->idx);
        if (l != sizeof(we)) {
                log_error("Couldn't write rfkill event structure, too short.");
                return -EIO;
        }

        log_debug("Loaded state '%s' from %s.", one_zero(b), state_file);
        return 0;
}

static int save_state(
                int rfkill_fd,
                struct udev *udev,
                const struct rfkill_event *event) {

        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        _cleanup_free_ char *state_file = NULL;
        int r;

        assert(rfkill_fd >= 0);
        assert(udev);
        assert(event);

        r = find_device(udev, event, &device);
        if (r < 0)
                return r;

        r = determine_state_file(udev, event, device, &state_file);
        if (r < 0)
                return r;

        r = write_string_file(state_file, one_zero(event->soft), WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write state file %s: %m", state_file);

        log_debug("Saved state '%s' to %s.", one_zero(event->soft), state_file);
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_close_ int rfkill_fd = -1;
        bool ready = false;
        int r, n;

        if (argc > 1) {
                log_error("This program requires no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        udev = udev_new();
        if (!udev) {
                r = log_oom();
                goto finish;
        }

        r = mkdir_p("/var/lib/systemd/rfkill", 0755);
        if (r < 0) {
                log_error_errno(r, "Failed to create rfkill directory: %m");
                goto finish;
        }

        n = sd_listen_fds(false);
        if (n < 0) {
                r = log_error_errno(n, "Failed to determine whether we got any file descriptors passed: %m");
                goto finish;
        }
        if (n > 1) {
                log_error("Got too many file descriptors.");
                r = -EINVAL;
                goto finish;
        }

        if (n == 0) {
                rfkill_fd = open("/dev/rfkill", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (rfkill_fd < 0) {
                        if (errno == ENOENT) {
                                log_debug_errno(errno, "Missing rfkill subsystem, or no device present, exiting.");
                                r = 0;
                                goto finish;
                        }

                        r = log_error_errno(errno, "Failed to open /dev/rfkill: %m");
                        goto finish;
                }
        } else {
                rfkill_fd = SD_LISTEN_FDS_START;

                r = fd_nonblock(rfkill_fd, 1);
                if (r < 0) {
                        log_error_errno(r, "Failed to make /dev/rfkill socket non-blocking: %m");
                        goto finish;
                }
        }

        for (;;) {
                struct rfkill_event event;
                const char *type;
                ssize_t l;

                l = read(rfkill_fd, &event, sizeof(event));
                if (l < 0) {
                        if (errno == EAGAIN) {

                                if (!ready) {
                                        /* Notify manager that we are
                                         * now finished with
                                         * processing whatever was
                                         * queued */
                                        (void) sd_notify(false, "READY=1");
                                        ready = true;
                                }

                                /* Hang around for a bit, maybe there's more coming */

                                r = fd_wait_for_event(rfkill_fd, POLLIN, EXIT_USEC);
                                if (r == -EINTR)
                                        continue;
                                if (r < 0) {
                                        log_error_errno(r, "Failed to poll() on device: %m");
                                        goto finish;
                                }
                                if (r > 0)
                                        continue;

                                log_debug("All events read and idle, exiting.");
                                break;
                        }

                        log_error_errno(errno, "Failed to read from /dev/rfkill: %m");
                }

                if (l != RFKILL_EVENT_SIZE_V1) {
                        log_error("Read event structure of invalid size.");
                        r = -EIO;
                        goto finish;
                }

                type = rfkill_type_to_string(event.type);
                if (!type) {
                        log_debug("An rfkill device of unknown type %i discovered, ignoring.", event.type);
                        continue;
                }

                switch (event.op) {

                case RFKILL_OP_ADD:
                        log_debug("A new rfkill device has been added with index %i and type %s.", event.idx, type);
                        (void) load_state(rfkill_fd, udev, &event);
                        break;

                case RFKILL_OP_DEL:
                        log_debug("An rfkill device has been removed with index %i and type %s", event.idx, type);
                        break;

                case RFKILL_OP_CHANGE:
                        log_debug("An rfkill device has changed state with index %i and type %s", event.idx, type);
                        (void) save_state(rfkill_fd, udev, &event);
                        break;

                default:
                        log_debug("Unknown event %i from /dev/rfkill for index %i and type %s, ignoring.", event.op, event.idx, type);
                        break;
                }
        }

        r = 0;

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
