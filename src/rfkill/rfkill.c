/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/rfkill.h>
#include <poll.h>

#include "sd-daemon.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "libudev-private.h"
#include "mkdir.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"
#include "list.h"

/* Note that any write is delayed until exit and the rfkill state will not be
 * stored for rfkill indices that disappear after a change. */
#define EXIT_USEC (5 * USEC_PER_SEC)

typedef struct write_queue_item {
        LIST_FIELDS(struct write_queue_item, queue);
        int rfkill_idx;
        char *file;
        int state;
} write_queue_item;

static struct write_queue_item* write_queue_item_free(struct write_queue_item *item) {
        if (!item)
                return NULL;

        free(item->file);
        return mfree(item);
}

static const char* const rfkill_type_table[NUM_RFKILL_TYPES] = {
        [RFKILL_TYPE_ALL] = "all",
        [RFKILL_TYPE_WLAN] = "wlan",
        [RFKILL_TYPE_BLUETOOTH] = "bluetooth",
        [RFKILL_TYPE_UWB] = "uwb",
        [RFKILL_TYPE_WIMAX] = "wimax",
        [RFKILL_TYPE_WWAN] = "wwan",
        [RFKILL_TYPE_GPS] = "gps",
        [RFKILL_TYPE_FM] = "fm",
        [RFKILL_TYPE_NFC] = "nfc",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(rfkill_type, int);

static int find_device(
                const struct rfkill_event *event,
                sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ char *sysname = NULL;
        const char *name;
        int r;

        assert(event);
        assert(ret);

        if (asprintf(&sysname, "rfkill%i", event->idx) < 0)
                return log_oom();

        r = sd_device_new_from_subsystem_sysname(&device, "rfkill", sysname);
        if (r < 0)
                return log_full_errno(IN_SET(r, -ENOENT, -ENXIO, -ENODEV) ? LOG_DEBUG : LOG_ERR, r,
                                      "Failed to open device '%s': %m", sysname);

        r = sd_device_get_sysattr_value(device, "name", &name);
        if (r < 0)
                return log_debug_errno(r, "Device has no name, ignoring: %m");

        log_debug("Operating on rfkill device '%s'.", name);

        *ret = TAKE_PTR(device);
        return 0;
}

static int wait_for_initialized(
                sd_device *device,
                sd_device **ret) {

        _cleanup_(udev_monitor_unrefp) struct udev_monitor *monitor = NULL;
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        int initialized, watch_fd, r;
        const char *sysname;

        assert(device);
        assert(ret);

        if (sd_device_get_is_initialized(device, &initialized) >= 0 && initialized) {
                *ret = sd_device_ref(device);
                return 0;
        }

        assert_se(sd_device_get_sysname(device, &sysname) >= 0);

        /* Wait until the device is initialized, so that we can get
         * access to the ID_PATH property */

        monitor = udev_monitor_new_from_netlink(NULL, "udev");
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
        r = sd_device_new_from_subsystem_sysname(&d, "rfkill", sysname);
        if (r < 0)
                return log_full_errno(IN_SET(r, -ENOENT, -ENXIO, -ENODEV) ? LOG_DEBUG : LOG_ERR, r,
                                      "Failed to open device '%s': %m", sysname);

        if (sd_device_get_is_initialized(d, &initialized) >= 0 && initialized) {
                *ret = TAKE_PTR(d);
                return 0;
        }

        for (;;) {
                _cleanup_(sd_device_unrefp) sd_device *t = NULL;
                const char *name;

                r = fd_wait_for_event(watch_fd, POLLIN, EXIT_USEC);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to watch udev monitor: %m");
                if (r == 0) {
                        log_error("Timed out waiting for udev monitor.");
                        return -ETIMEDOUT;
                }

                r = udev_monitor_receive_sd_device(monitor, &t);
                if (r < 0)
                        continue;

                if (sd_device_get_sysname(t, &name) >= 0 && streq(name, sysname)) {
                        *ret = TAKE_PTR(t);
                        return 0;
                }
        }
}

static int determine_state_file(
                const struct rfkill_event *event,
                char **ret) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL, *device = NULL;
        const char *path_id, *type;
        char *state_file;
        int r;

        assert(event);
        assert(ret);

        r = find_device(event, &d);
        if (r < 0)
                return r;

        r = wait_for_initialized(d, &device);
        if (r < 0)
                return r;

        assert_se(type = rfkill_type_to_string(event->type));

        if (sd_device_get_property_value(device, "ID_PATH", &path_id) >= 0) {
                _cleanup_free_ char *escaped_path_id = NULL;

                escaped_path_id = cescape(path_id);
                if (!escaped_path_id)
                        return log_oom();

                state_file = strjoin("/var/lib/systemd/rfkill/", escaped_path_id, ":", type);
        } else
                state_file = strjoin("/var/lib/systemd/rfkill/", type);

        if (!state_file)
                return log_oom();

        *ret = state_file;
        return 0;
}

static int load_state(
                int rfkill_fd,
                const struct rfkill_event *event) {

        _cleanup_free_ char *state_file = NULL, *value = NULL;
        struct rfkill_event we;
        ssize_t l;
        int b, r;

        assert(rfkill_fd >= 0);
        assert(event);

        if (shall_restore_state() == 0)
                return 0;

        r = determine_state_file(event, &state_file);
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

static void save_state_queue_remove(
                struct write_queue_item **write_queue,
                int idx,
                char *state_file) {

        struct write_queue_item *item, *tmp;

        LIST_FOREACH_SAFE(queue, item, tmp, *write_queue) {
                if ((state_file && streq(item->file, state_file)) || idx == item->rfkill_idx) {
                        log_debug("Canceled previous save state of '%s' to %s.", one_zero(item->state), item->file);
                        LIST_REMOVE(queue, *write_queue, item);
                        write_queue_item_free(item);
                }
        }
}

static int save_state_queue(
                struct write_queue_item **write_queue,
                int rfkill_fd,
                const struct rfkill_event *event) {

        _cleanup_free_ char *state_file = NULL;
        struct write_queue_item *item;
        int r;

        assert(rfkill_fd >= 0);
        assert(event);

        r = determine_state_file(event, &state_file);
        if (r < 0)
                return r;

        save_state_queue_remove(write_queue, event->idx, state_file);

        item = new0(struct write_queue_item, 1);
        if (!item)
                return -ENOMEM;

        item->file = TAKE_PTR(state_file);
        item->rfkill_idx = event->idx;
        item->state = event->soft;

        LIST_APPEND(queue, *write_queue, item);

        return 0;
}

static int save_state_cancel(
                struct write_queue_item **write_queue,
                int rfkill_fd,
                const struct rfkill_event *event) {

        _cleanup_free_ char *state_file = NULL;
        int r;

        assert(rfkill_fd >= 0);
        assert(event);

        r = determine_state_file(event, &state_file);
        save_state_queue_remove(write_queue, event->idx, state_file);
        if (r < 0)
                return r;

        return 0;
}

static int save_state_write(struct write_queue_item **write_queue) {
        struct write_queue_item *item, *tmp;
        int result = 0;
        bool error_logged = false;
        int r;

        LIST_FOREACH_SAFE(queue, item, tmp, *write_queue) {
                r = write_string_file(item->file, one_zero(item->state), WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
                if (r < 0) {
                        result = r;
                        if (!error_logged) {
                                log_error_errno(r, "Failed to write state file %s: %m", item->file);
                                error_logged = true;
                        } else
                                log_warning_errno(r, "Failed to write state file %s: %m", item->file);
                } else
                        log_debug("Saved state '%s' to %s.", one_zero(item->state), item->file);

                LIST_REMOVE(queue, *write_queue, item);
                write_queue_item_free(item);
        }
        return result;
}

int main(int argc, char *argv[]) {
        LIST_HEAD(write_queue_item, write_queue);
        _cleanup_close_ int rfkill_fd = -1;
        bool ready = false;
        int r, n;

        if (argc > 1) {
                log_error("This program requires no arguments.");
                return EXIT_FAILURE;
        }

        LIST_HEAD_INIT(write_queue);

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

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
                        (void) load_state(rfkill_fd, &event);
                        break;

                case RFKILL_OP_DEL:
                        log_debug("An rfkill device has been removed with index %i and type %s", event.idx, type);
                        (void) save_state_cancel(&write_queue, rfkill_fd, &event);
                        break;

                case RFKILL_OP_CHANGE:
                        log_debug("An rfkill device has changed state with index %i and type %s", event.idx, type);
                        (void) save_state_queue(&write_queue, rfkill_fd, &event);
                        break;

                default:
                        log_debug("Unknown event %i from /dev/rfkill for index %i and type %s, ignoring.", event.op, event.idx, type);
                        break;
                }
        }

        r = 0;

finish:
        (void) save_state_write(&write_queue);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
