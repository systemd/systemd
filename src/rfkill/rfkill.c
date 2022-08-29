/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/rfkill.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "device-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "list.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "reboot-util.h"
#include "string-table.h"
#include "string-util.h"
#include "udev-util.h"
#include "util.h"

/* Note that any write is delayed until exit and the rfkill state will not be
 * stored for rfkill indices that disappear after a change. */
#define EXIT_USEC (5 * USEC_PER_SEC)

typedef struct write_queue_item {
        LIST_FIELDS(struct write_queue_item, queue);
        int rfkill_idx;
        char *file;
        int state;
} write_queue_item;

typedef struct Context {
        LIST_HEAD(write_queue_item, write_queue);
        int rfkill_fd;
} Context;

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

        if (asprintf(&sysname, "rfkill%u", event->idx) < 0)
                return log_oom();

        r = sd_device_new_from_subsystem_sysname(&device, "rfkill", sysname);
        if (r < 0)
                return log_full_errno(ERRNO_IS_DEVICE_ABSENT(r) ? LOG_DEBUG : LOG_ERR, r,
                                      "Failed to open device '%s': %m", sysname);

        r = sd_device_get_sysattr_value(device, "name", &name);
        if (r < 0)
                return log_device_debug_errno(device, r, "Device has no name, ignoring: %m");

        log_device_debug(device, "Operating on rfkill device '%s'.", name);

        *ret = TAKE_PTR(device);
        return 0;
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

        r = device_wait_for_initialization(d, "rfkill", USEC_INFINITY, &device);
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

static int load_state(Context *c, const struct rfkill_event *event) {
        _cleanup_free_ char *state_file = NULL, *value = NULL;
        int b, r;

        assert(c);
        assert(c->rfkill_fd >= 0);
        assert(event);

        if (shall_restore_state() == 0)
                return 0;

        r = determine_state_file(event, &state_file);
        if (r < 0)
                return r;

        r = read_one_line_file(state_file, &value);
        if (IN_SET(r, -ENOENT, 0)) {
                /* No state file or it's truncated? Then save the current state */

                r = write_string_file(state_file, one_zero(event->soft), WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
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

        struct rfkill_event we = {
                .idx = event->idx,
                .op = RFKILL_OP_CHANGE,
                .soft = b,
        };
        assert_cc(offsetof(struct rfkill_event, op) < RFKILL_EVENT_SIZE_V1);
        assert_cc(offsetof(struct rfkill_event, soft) < RFKILL_EVENT_SIZE_V1);

        ssize_t l = write(c->rfkill_fd, &we, sizeof we);
        if (l < 0)
                return log_error_errno(errno, "Failed to restore rfkill state for %u: %m", event->idx);
        if ((size_t)l < RFKILL_EVENT_SIZE_V1) /* l cannot be < 0 here. Cast to fix -Werror=sign-compare */
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Couldn't write rfkill event structure, too short (wrote %zd of %zu bytes).",
                                       l, sizeof we);
        log_debug("Writing struct rfkill_event successful (%zd of %zu bytes).", l, sizeof we);

        log_debug("Loaded state '%s' from %s.", one_zero(b), state_file);
        return 0;
}

static void save_state_queue_remove(Context *c, int idx, const char *state_file) {
        assert(c);

        LIST_FOREACH(queue, item, c->write_queue)
                if ((state_file && streq(item->file, state_file)) || idx == item->rfkill_idx) {
                        log_debug("Canceled previous save state of '%s' to %s.", one_zero(item->state), item->file);
                        LIST_REMOVE(queue, c->write_queue, item);
                        write_queue_item_free(item);
                }
}

static int save_state_queue(Context *c, const struct rfkill_event *event) {
        _cleanup_free_ char *state_file = NULL;
        struct write_queue_item *item;
        int r;

        assert(c);
        assert(c->rfkill_fd >= 0);
        assert(event);

        r = determine_state_file(event, &state_file);
        if (r < 0)
                return r;

        save_state_queue_remove(c, event->idx, state_file);

        item = new0(struct write_queue_item, 1);
        if (!item)
                return -ENOMEM;

        item->file = TAKE_PTR(state_file);
        item->rfkill_idx = event->idx;
        item->state = event->soft;

        LIST_APPEND(queue, c->write_queue, item);

        return 0;
}

static int save_state_cancel(Context *c, const struct rfkill_event *event) {
        _cleanup_free_ char *state_file = NULL;
        int r;

        assert(c);
        assert(c->rfkill_fd >= 0);
        assert(event);

        r = determine_state_file(event, &state_file);
        save_state_queue_remove(c, event->idx, state_file);
        if (r < 0)
                return r;

        return 0;
}

static int save_state_write_one(struct write_queue_item *item) {
        int r;

        r = write_string_file(item->file, one_zero(item->state), WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write state file %s: %m", item->file);

        log_debug("Saved state '%s' to %s.", one_zero(item->state), item->file);
        return 0;
}

static void context_save_and_clear(Context *c) {
        struct write_queue_item *i;

        assert(c);

        while ((i = c->write_queue)) {
                LIST_REMOVE(queue, c->write_queue, i);
                (void) save_state_write_one(i);
                write_queue_item_free(i);
        }

        safe_close(c->rfkill_fd);
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_save_and_clear) Context c = { .rfkill_fd = -1 };
        bool ready = false;
        int r, n;

        if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires no arguments.");

        log_setup();

        umask(0022);

        n = sd_listen_fds(false);
        if (n < 0)
                return log_error_errno(n, "Failed to determine whether we got any file descriptors passed: %m");
        if (n > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Got too many file descriptors.");

        if (n == 0) {
                c.rfkill_fd = open("/dev/rfkill", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
                if (c.rfkill_fd < 0) {
                        if (errno == ENOENT) {
                                log_debug_errno(errno, "Missing rfkill subsystem, or no device present, exiting.");
                                return 0;
                        }

                        return log_error_errno(errno, "Failed to open /dev/rfkill: %m");
                }
        } else {
                c.rfkill_fd = SD_LISTEN_FDS_START;

                r = fd_nonblock(c.rfkill_fd, 1);
                if (r < 0)
                        return log_error_errno(r, "Failed to make /dev/rfkill socket non-blocking: %m");
        }

        for (;;) {
                struct rfkill_event event = {};

                ssize_t l = read(c.rfkill_fd, &event, sizeof event);
                if (l < 0) {
                        if (errno != EAGAIN)
                                return log_error_errno(errno, "Failed to read from /dev/rfkill: %m");

                        if (!ready) {
                                /* Notify manager that we are now finished with processing whatever was
                                 * queued */
                                r = sd_notify(false, "READY=1");
                                if (r < 0)
                                        log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

                                ready = true;
                        }

                        /* Hang around for a bit, maybe there's more coming */

                        r = fd_wait_for_event(c.rfkill_fd, POLLIN, EXIT_USEC);
                        if (r == -EINTR)
                                continue;
                        if (r < 0)
                                return log_error_errno(r, "Failed to poll() on device: %m");
                        if (r > 0)
                                continue;

                        log_debug("All events read and idle, exiting.");
                        break;
                }

                if ((size_t)l < RFKILL_EVENT_SIZE_V1) /* l cannot be < 0 here. Cast to fix -Werror=sign-compare */
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read of struct rfkill_event: (%zd < %zu)",
                                               l, (size_t) RFKILL_EVENT_SIZE_V1); /* Casting necessary to make compiling with different kernel versions happy */
                log_debug("Reading struct rfkill_event: got %zd bytes.", l);

                /* The event structure has more fields. We only care about the first few, so it's OK if we
                 * don't read the full structure. */
                assert_cc(offsetof(struct rfkill_event, op) < RFKILL_EVENT_SIZE_V1);
                assert_cc(offsetof(struct rfkill_event, type) < RFKILL_EVENT_SIZE_V1);

                const char *type = rfkill_type_to_string(event.type);
                if (!type) {
                        log_debug("An rfkill device of unknown type %u discovered, ignoring.", event.type);
                        continue;
                }

                switch (event.op) {

                case RFKILL_OP_ADD:
                        log_debug("A new rfkill device has been added with index %u and type %s.", event.idx, type);
                        (void) load_state(&c, &event);
                        break;

                case RFKILL_OP_DEL:
                        log_debug("An rfkill device has been removed with index %u and type %s", event.idx, type);
                        (void) save_state_cancel(&c, &event);
                        break;

                case RFKILL_OP_CHANGE:
                        log_debug("An rfkill device has changed state with index %u and type %s", event.idx, type);
                        (void) save_state_queue(&c, &event);
                        break;

                default:
                        log_debug("Unknown event %u from /dev/rfkill for index %u and type %s, ignoring.", event.op, event.idx, type);
                        break;
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
