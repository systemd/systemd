/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "logind.h"
#include "logind-action.h"
#include "logind-button.h"
#include "logind-device.h"
#include "logind-seat.h"
#include "logind-session.h"
#include "logind-user.h"
#include "sleep-config.h"
#include "test-tables.h"
#include "tests.h"
#include "time-util.h"

static void test_sleep_handle_action(void) {
        for (HandleAction action = _HANDLE_ACTION_SLEEP_FIRST; action < _HANDLE_ACTION_SLEEP_LAST; action++) {
                const HandleActionData *data;
                const char *sleep_operation_str, *handle_action_str;

                assert_se(data = handle_action_lookup(action));

                assert_se(handle_action_str = handle_action_to_string(action));
                assert_se(sleep_operation_str = sleep_operation_to_string(data->sleep_operation));

                assert_se(streq(handle_action_str, sleep_operation_str));
        }
}

static int dummy_time_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        return 0;
}

/* Verify that button_free() cancels the Manager-scoped long-press timer the Button armed, and at the same
 * time leaves a timer armed by a different Button alone. */
static void test_button_free_cancels_long_press(void) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(hashmap_freep) Hashmap *buttons = NULL;
        _cleanup_free_ Manager *m = NULL;
        Button *b, *b2;

        assert_se(m = new0(Manager, 1));
        assert_se(sd_event_new(&e) >= 0);
        assert_se(buttons = hashmap_new(&string_hash_ops));
        m->event = e;
        m->buttons = buttons;

        assert_se(b = button_new(m, "test-button"));
        assert_se(b2 = button_new(m, "other-button"));

        /* Arm a long-press timer owned by b, exactly as start_long_press() does: the source lives in
         * a Manager-scoped field and carries the Button as userdata. */
        assert_se(sd_event_add_time_relative(e, &m->power_key_long_press_event_source, CLOCK_MONOTONIC,
                                             10 * USEC_PER_SEC, 0, dummy_time_handler, b) >= 0);
        /* ... and another one owned by b2. */
        assert_se(sd_event_add_time_relative(e, &m->reboot_key_long_press_event_source, CLOCK_MONOTONIC,
                                             10 * USEC_PER_SEC, 0, dummy_time_handler, b2) >= 0);

        /* Freeing b must cancel the timer b armed. */
        button_free(b);
        assert_se(!m->power_key_long_press_event_source);

        /* ... but freeing b must not touch a timer owned by another Button. */
        assert_se(m->reboot_key_long_press_event_source);

        button_free(b2);
        assert_se(!m->reboot_key_long_press_event_source);
}

/* Verify that seat_free() does not leave itself on the GC queue when draining a device re-queues it:
 * device_detach() calls seat_add_to_gc_queue() once the seat loses its last master device, so a
 * seat_free() that dropped itself from the queue before that drain would leave the freed seat dangling
 * at the queue head for the next manager_gc() pass. */
static void test_seat_free_dequeues_on_device_detach(void) {
        _cleanup_(hashmap_freep) Hashmap *seats = NULL;
        _cleanup_(hashmap_freep) Hashmap *devices = NULL;
        _cleanup_free_ Manager *m = NULL;
        Seat *s;
        Device *d;

        assert_se(m = new0(Manager, 1));
        assert_se(seats = hashmap_new(&string_hash_ops));
        assert_se(devices = hashmap_new(&string_hash_ops));
        m->seats = seats;
        m->devices = devices;

        assert_se(seat_new(m, "seattest", &s) >= 0);

        /* A non-master device: the seat has no master, so detaching it re-queues the seat for GC. */
        assert_se(d = device_new(m, "/sys/devices/platform/test-seat-device", /* master= */ false));
        device_attach(d, s);

        /* Mimic manager_gc() having popped the seat off the queue right before freeing it. */
        assert_se(!s->in_gc_queue);
        assert_se(!m->seat_gc_queue);

        seat_free(s);

        /* Freeing the seat drained the device, which re-queued the (now freed) seat. seat_free() must
         * have removed it again, otherwise the queue head is a dangling pointer. */
        assert_se(!m->seat_gc_queue);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(HandleAction, handle_action, HANDLE_ACTION);
        test_table(InhibitMode, inhibit_mode, INHIBIT_MODE);
        test_table(KillWhom, kill_whom, KILL_WHOM);
        test_table(SessionClass, session_class, SESSION_CLASS);
        test_table(SessionState, session_state, SESSION_STATE);
        test_table(SessionType, session_type, SESSION_TYPE);
        test_table(UserState, user_state, USER_STATE);

        test_sleep_handle_action();
        test_button_free_cancels_long_press();
        test_seat_free_dequeues_on_device_detach();

        return EXIT_SUCCESS;
}
