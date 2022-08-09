/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-util.h"
#include "device-util.h"
#include "hash-funcs.h"
#include "logind-brightness.h"
#include "logind.h"
#include "process-util.h"
#include "stdio-util.h"

/* Brightness and LED devices tend to be very slow to write to (often being I2C and such). Writes to the
 * sysfs attributes are synchronous, and hence will freeze our process on access. We can't really have that,
 * hence we add some complexity: whenever we need to write to the brightness attribute, we do so in a forked
 * off process, which terminates when it is done. Watching that process allows us to watch completion of the
 * write operation.
 *
 * To make this even more complex: clients are likely to send us many write requests in a short time-frame
 * (because they implement reactive brightness sliders on screen). Let's coalesce writes to make this
 * efficient: whenever we get requests to change brightness while we are still writing to the brightness
 * attribute, let's remember the request and restart a new one when the initial operation finished. When we
 * get another request while one is ongoing and one is pending we'll replace the pending one with the new
 * one.
 *
 * The bus messages are answered when the first write operation finishes that started either due to the
 * request or due to a later request that overrode the requested one.
 *
 * Yes, this is complex, but I don't see an easier way if we want to be both efficient and still support
 * completion notification. */

typedef struct BrightnessWriter {
        Manager *manager;

        sd_device *device;
        char *path;

        pid_t child;

        uint32_t brightness;
        bool again;

        Set *current_messages;
        Set *pending_messages;

        sd_event_source* child_event_source;
} BrightnessWriter;

static BrightnessWriter* brightness_writer_free(BrightnessWriter *w) {
        if (!w)
                return NULL;

        if (w->manager && w->path)
                (void) hashmap_remove_value(w->manager->brightness_writers, w->path, w);

        sd_device_unref(w->device);
        free(w->path);

        set_free(w->current_messages);
        set_free(w->pending_messages);

        w->child_event_source = sd_event_source_unref(w->child_event_source);

        return mfree(w);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(BrightnessWriter*, brightness_writer_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                brightness_writer_hash_ops,
                char,
                string_hash_func,
                string_compare_func,
                BrightnessWriter,
                brightness_writer_free);

static void brightness_writer_reply(BrightnessWriter *w, int error) {
        int r;

        assert(w);

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                m = set_steal_first(w->current_messages);
                if (!m)
                        break;

                if (error == 0)
                        r = sd_bus_reply_method_return(m, NULL);
                else
                        r = sd_bus_reply_method_errnof(m, error, "Failed to write to brightness device: %m");
                if (r < 0)
                        log_warning_errno(r, "Failed to send method reply, ignoring: %m");
        }
}

static int brightness_writer_fork(BrightnessWriter *w);

static int on_brightness_writer_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        BrightnessWriter *w = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(si);

        assert(si->si_pid == w->child);
        w->child = 0;
        w->child_event_source = sd_event_source_unref(w->child_event_source);

        brightness_writer_reply(w,
                                si->si_code == CLD_EXITED &&
                                si->si_status == EXIT_SUCCESS ? 0 : -EPROTO);

        if (w->again) {
                /* Another request to change the brightness has been queued. Act on it, but make the pending
                 * messages the current ones. */
                w->again = false;
                set_free(w->current_messages);
                w->current_messages = TAKE_PTR(w->pending_messages);

                r = brightness_writer_fork(w);
                if (r >= 0)
                        return 0;

                brightness_writer_reply(w, r);
        }

        brightness_writer_free(w);
        return 0;
}

static int brightness_writer_fork(BrightnessWriter *w) {
        int r;

        assert(w);
        assert(w->manager);
        assert(w->child == 0);
        assert(!w->child_event_source);

        r = safe_fork("(sd-bright)", FORK_DEATHSIG|FORK_NULL_STDIO|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_REOPEN_LOG, &w->child);
        if (r < 0)
                return r;
        if (r == 0) {
                char brs[DECIMAL_STR_MAX(uint32_t)+1];

                /* Child */
                xsprintf(brs, "%" PRIu32, w->brightness);

                r = sd_device_set_sysattr_value(w->device, "brightness", brs);
                if (r < 0) {
                        log_device_error_errno(w->device, r, "Failed to write brightness to device: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        r = sd_event_add_child(w->manager->event, &w->child_event_source, w->child, WEXITED, on_brightness_writer_exit, w);
        if (r < 0)
                return log_error_errno(r, "Failed to watch brightness writer child " PID_FMT ": %m", w->child);

        return 0;
}

static int set_add_message(Set **set, sd_bus_message *message) {
        int r;

        assert(set);

        if (!message)
                return 0;

        r = sd_bus_message_get_expect_reply(message);
        if (r <= 0)
                return r;

        r = set_ensure_put(set, &bus_message_hash_ops, message);
        if (r <= 0)
                return r;
        sd_bus_message_ref(message);

        return 1;
}

int manager_write_brightness(
                Manager *m,
                sd_device *device,
                uint32_t brightness,
                sd_bus_message *message) {

        _cleanup_(brightness_writer_freep) BrightnessWriter *w = NULL;
        BrightnessWriter *existing;
        const char *path;
        int r;

        assert(m);
        assert(device);

        r = sd_device_get_syspath(device, &path);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get sysfs path for brightness device: %m");

        existing = hashmap_get(m->brightness_writers, path);
        if (existing) {
                /* There's already a writer for this device. Let's update it with the new brightness, and add
                 * our message to the set of message to reply when done. */

                r = set_add_message(&existing->pending_messages, message);
                if (r < 0)
                        return log_error_errno(r, "Failed to add message to set: %m");

                /* We override any previously requested brightness here: we coalesce writes, and the newest
                 * requested brightness is the one we'll put into effect. */
                existing->brightness = brightness;
                existing->again = true; /* request another iteration of the writer when the current one is
                                         * complete */
                return 0;
        }

        w = new(BrightnessWriter, 1);
        if (!w)
                return log_oom();

        *w = (BrightnessWriter) {
                .device = sd_device_ref(device),
                .path = strdup(path),
                .brightness = brightness,
        };

        if (!w->path)
                return log_oom();

        r = hashmap_ensure_put(&m->brightness_writers, &brightness_writer_hash_ops, w->path, w);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to add brightness writer to hashmap: %m");

        w->manager = m;

        r = set_add_message(&w->current_messages, message);
        if (r < 0)
                return log_error_errno(r, "Failed to add message to set: %m");

        r = brightness_writer_fork(w);
        if (r < 0)
                return r;

        TAKE_PTR(w);
        return 0;
}
