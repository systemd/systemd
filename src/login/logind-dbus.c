/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-device.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "audit-util.h"
#include "bitfield.h"
#include "bootspec.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-get-properties.h"
#include "bus-locator.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "device-util.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "efivars.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "event-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "login-util.h"
#include "logind-session.h"
#include "logind.h"
#include "logind-action.h"
#include "logind-dbus.h"
#include "logind-polkit.h"
#include "logind-seat.h"
#include "logind-seat-dbus.h"
#include "logind-session-dbus.h"
#include "logind-user.h"
#include "logind-user-dbus.h"
#include "logind-utmp.h"
#include "mkdir-label.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "reboot-util.h"
#include "serialize.h"
#include "signal-util.h"
#include "sleep-config.h"
#include "stdio-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "unit-def.h"
#include "user-record.h"
#include "user-util.h"
#include "virt.h"
#include "wall.h"

/* As a random fun fact sysvinit had a 252 (256-(strlen(" \r\n")+1))
 * character limit for the wall message.
 * https://git.savannah.nongnu.org/cgit/sysvinit.git/tree/src/shutdown.c#n72
 * There is no real technical need for that but doesn't make sense
 * to store arbitrary amounts either. As we are not stingy here, we
 * allow 4k.
 */
#define WALL_MESSAGE_MAX 4096U

#define SHUTDOWN_SCHEDULE_FILE "/run/systemd/shutdown/scheduled"

static void reset_scheduled_shutdown(Manager *m);

static int get_sender_session(
                Manager *m,
                sd_bus_message *message,
                bool consult_display,
                sd_bus_error *error,
                Session **ret) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Session *session = NULL;
        const char *name;
        int r;

        assert(m);

        /* Acquire the sender's session. This first checks if the sending process is inside a session itself,
         * and returns that. If not and 'consult_display' is true, this returns the display session of the
         * owning user of the caller. */

        r = sd_bus_query_sender_creds(message,
                                      SD_BUS_CREDS_SESSION|SD_BUS_CREDS_AUGMENT|
                                      (consult_display ? SD_BUS_CREDS_OWNER_UID : 0), &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_session(creds, &name);
        if (r < 0) {
                if (r != -ENXIO)
                        return r;

                if (consult_display) {
                        uid_t uid;

                        r = sd_bus_creds_get_owner_uid(creds, &uid);
                        if (r < 0) {
                                if (r != -ENXIO)
                                        return r;
                        } else {
                                User *user;

                                user = hashmap_get(m->users, UID_TO_PTR(uid));
                                if (user)
                                        session = user->display;
                        }
                }
        } else
                session = hashmap_get(m->sessions, name);

        if (!session)
                return sd_bus_error_set(error, BUS_ERROR_NO_SESSION_FOR_PID,
                                        consult_display ?
                                        "Caller does not belong to any known session and doesn't own any suitable session." :
                                        "Caller does not belong to any known session.");

        *ret = session;
        return 0;
}

int manager_get_session_from_creds(
                Manager *m,
                sd_bus_message *message,
                const char *name,
                sd_bus_error *error,
                Session **ret) {

        Session *session;

        assert(m);
        assert(ret);

        if (session_is_self(name)) /* the caller's own session */
                return get_sender_session(m, message, false, error, ret);
        if (session_is_auto(name)) /* The caller's own session if they have one, otherwise their user's display session */
                return get_sender_session(m, message, true, error, ret);

        session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SESSION, "No session '%s' known", name);

        *ret = session;
        return 0;
}

static int get_sender_user(Manager *m, sd_bus_message *message, sd_bus_error *error, User **ret) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t uid;
        User *user;
        int r;

        /* Note that we get the owner UID of the session, not the actual client UID here! */
        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_owner_uid(creds, &uid);
        if (r < 0) {
                if (r != -ENXIO)
                        return r;

                user = NULL;
        } else
                user = hashmap_get(m->users, UID_TO_PTR(uid));

        if (!user)
                return sd_bus_error_set(error, BUS_ERROR_NO_USER_FOR_PID,
                                        "Caller does not belong to any logged in or lingering user");

        *ret = user;
        return 0;
}

int manager_get_user_from_creds(Manager *m, sd_bus_message *message, uid_t uid, sd_bus_error *error, User **ret) {
        User *user;

        assert(m);
        assert(ret);

        if (!uid_is_valid(uid))
                return get_sender_user(m, message, error, ret);

        user = hashmap_get(m->users, UID_TO_PTR(uid));
        if (!user)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_USER,
                                         "User ID "UID_FMT" is not logged in or lingering", uid);

        *ret = user;
        return 0;
}

int manager_get_seat_from_creds(
                Manager *m,
                sd_bus_message *message,
                const char *name,
                sd_bus_error *error,
                Seat **ret) {

        Seat *seat;
        int r;

        assert(m);
        assert(ret);

        if (seat_is_self(name) || seat_is_auto(name)) {
                Session *session;

                /* Use these special seat names as session names */
                r = manager_get_session_from_creds(m, message, name, error, &session);
                if (r < 0)
                        return r;

                seat = session->seat;
                if (!seat)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "Session '%s' has no seat.", session->id);
        } else {
                seat = hashmap_get(m->seats, name);
                if (!seat)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT, "No seat '%s' known", name);
        }

        *ret = seat;
        return 0;
}

static int return_test_polkit(
                sd_bus_message *message,
                const char *action,
                const char **details,
                uid_t good_user,
                sd_bus_error *e) {

        const char *result;
        bool challenge;
        int r;

        r = bus_test_polkit(message, action, details, good_user, &challenge, e);
        if (r < 0)
                return r;

        if (r > 0)
                result = "yes";
        else if (challenge)
                result = "challenge";
        else
                result = "no";

        return sd_bus_reply_method_return(message, "s", result);
}

static int property_get_idle_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", manager_get_idle_hint(m, NULL) > 0);
}

static int property_get_idle_since_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        dual_timestamp t = DUAL_TIMESTAMP_NULL;

        assert(bus);
        assert(reply);

        manager_get_idle_hint(m, &t);

        return sd_bus_message_append(reply, "t", streq(property, "IdleSinceHint") ? t.realtime : t.monotonic);
}

static int property_get_inhibited(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        InhibitWhat w;

        assert(bus);
        assert(reply);

        if (streq(property, "BlockInhibited"))
                w = manager_inhibit_what(m, INHIBIT_BLOCK);
        else if (streq(property, "BlockWeakInhibited"))
                w = manager_inhibit_what(m, INHIBIT_BLOCK_WEAK);
        else if (streq(property, "DelayInhibited"))
                w = manager_inhibit_what(m, INHIBIT_DELAY);
        else
                assert_not_reached();

        return sd_bus_message_append(reply, "s", inhibit_what_to_string(w));
}

static int property_get_preparing(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        bool b = false;

        assert(bus);
        assert(reply);

        if (m->delayed_action) {
                if (streq(property, "PreparingForShutdown"))
                        b = m->delayed_action->inhibit_what & INHIBIT_SHUTDOWN;
                else
                        b = m->delayed_action->inhibit_what & INHIBIT_SLEEP;
        }

        return sd_bus_message_append(reply, "b", b);
}

static int property_get_preparing_shutdown_with_metadata(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        if (!m->delayed_action || !(m->delayed_action->inhibit_what & INHIBIT_SHUTDOWN))
                return sd_bus_message_append(reply, "a{sv}", 1, "preparing", "b", false);

        return sd_bus_message_append(
                        reply,
                        "a{sv}",
                        2,
                        "preparing",
                        "b",
                        true,
                        "type",
                        "s",
                        handle_action_to_string(m->delayed_action->handle));
}

static int property_get_sleep_operations(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **actions = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = handle_action_get_enabled_sleep_actions(m->handle_action_sleep_mask, &actions);
        if (r < 0)
                return r;

        return sd_bus_message_append_strv(reply, actions);
}

static int property_get_scheduled_shutdown(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'r', "st");
        if (r < 0)
                return r;

        if (m->delayed_action) {
                usec_t t = m->scheduled_shutdown_timeout; /* fall back to the schedule time on failure below */

                if (m->inhibit_timeout_source) {
                        r = sd_event_source_get_time(m->inhibit_timeout_source, &t);
                        if (r < 0)
                                log_debug_errno(r, "Failed to get time of inhibit timeout event source, ignoring: %m");
                }

                r = sd_bus_message_append(
                                reply, "st",
                                handle_action_to_string(m->delayed_action->handle), t);
        } else
                r = sd_bus_message_append(
                                reply, "st",
                                handle_action_to_string(m->scheduled_shutdown_action),
                                m->scheduled_shutdown_timeout);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

static int property_get_maintenance_time(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_free_ char *s = NULL;
        int r;

        assert(bus);
        assert(reply);

        if (m->maintenance_time) {
                r = calendar_spec_to_string(m->maintenance_time, &s);
                if (r < 0)
                        return log_error_errno(r, "Failed to format calendar specification: %m");
        }

        return sd_bus_message_append(reply, "s", s);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_handle_action, handle_action, HandleAction);
static BUS_DEFINE_PROPERTY_GET(property_get_docked, "b", Manager, manager_is_docked_or_external_displays);
static BUS_DEFINE_PROPERTY_GET(property_get_lid_closed, "b", Manager, manager_is_lid_closed);
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_on_external_power, "b", manager_is_on_external_power());
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_compat_user_tasks_max, "t", CGROUP_LIMIT_MAX);
static BUS_DEFINE_PROPERTY_GET_REF(property_get_hashmap_size, "t", Hashmap *, (uint64_t) hashmap_size);

static int method_get_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Session *session;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        p = session_bus_path(session);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

/* Get login session of a process.  This is not what you are looking for these days,
 * as apps may instead belong to a user service unit.  This includes terminal
 * emulators and hence command-line apps. */
static int method_get_session_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_free_ char *p = NULL;
        Session *session = NULL;
        pid_t pid;
        int r;

        assert(message);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;
        if (pid < 0)
                return -EINVAL;

        if (pid == 0) {
                r = manager_get_session_from_creds(m, message, NULL, error, &session);
                if (r < 0)
                        return r;
        } else {
                r = manager_get_session_by_pidref(m, &PIDREF_MAKE_FROM_PID(pid), &session);
                if (r < 0)
                        return r;

                if (!session)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SESSION_FOR_PID,
                                                 "PID "PID_FMT" does not belong to any known session", pid);
        }

        p = session_bus_path(session);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uint32_t uid;
        User *user;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        r = manager_get_user_from_creds(m, message, uid, error, &user);
        if (r < 0)
                return r;

        p = user_bus_path(user);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_user_by_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        User *user = NULL;
        pid_t pid;
        int r;

        assert(message);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(message, "u", &pid);
        if (r < 0)
                return r;
        if (pid < 0)
                return -EINVAL;

        if (pid == 0) {
                r = manager_get_user_from_creds(m, message, UID_INVALID, error, &user);
                if (r < 0)
                        return r;
        } else {
                r = manager_get_user_by_pid(m, pid, &user);
                if (r < 0)
                        return r;
                if (!user)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_USER_FOR_PID,
                                                 "PID "PID_FMT" does not belong to any logged in user or lingering user",
                                                 pid);
        }

        p = user_bus_path(user);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_get_seat(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *p = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Seat *seat;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_seat_from_creds(m, message, name, error, &seat);
        if (r < 0)
                return r;

        p = seat_bus_path(seat);
        if (!p)
                return -ENOMEM;

        return sd_bus_reply_method_return(message, "o", p);
}

static int method_list_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(susso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(session, m->sessions) {
                _cleanup_free_ char *p = NULL;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(susso)",
                                          session->id,
                                          (uint32_t) session->user->user_record->uid,
                                          session->user->user_record->user_name,
                                          session->seat ? session->seat->id : "",
                                          p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_sessions_ex(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(sussussbto)");
        if (r < 0)
                return r;

        Session *s;
        HASHMAP_FOREACH(s, m->sessions) {
                _cleanup_free_ char *path = NULL;
                dual_timestamp idle_ts;
                bool idle;

                assert(s->user);

                path = session_bus_path(s);
                if (!path)
                        return -ENOMEM;

                r = session_get_idle_hint(s, &idle_ts);
                if (r < 0)
                        return r;
                idle = r > 0;

                r = sd_bus_message_append(reply, "(sussussbto)",
                                          s->id,
                                          (uint32_t) s->user->user_record->uid,
                                          s->user->user_record->user_name,
                                          s->seat ? s->seat->id : "",
                                          (uint32_t) s->leader.pid,
                                          session_class_to_string(s->class),
                                          s->tty,
                                          idle,
                                          idle_ts.monotonic,
                                          path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_users(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        User *user;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(uso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(user, m->users) {
                _cleanup_free_ char *p = NULL;

                p = user_bus_path(user);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(uso)",
                                          (uint32_t) user->user_record->uid,
                                          user->user_record->user_name,
                                          p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_seats(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Seat *seat;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(so)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(seat, m->seats) {
                _cleanup_free_ char *p = NULL;

                p = seat_bus_path(seat);
                if (!p)
                        return -ENOMEM;

                r = sd_bus_message_append(reply, "(so)", seat->id, p);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_list_inhibitors(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Inhibitor *inhibitor;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ssssuu)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(inhibitor, m->inhibitors) {

                r = sd_bus_message_append(reply, "(ssssuu)",
                                          strempty(inhibit_what_to_string(inhibitor->what)),
                                          strempty(inhibitor->who),
                                          strempty(inhibitor->why),
                                          strempty(inhibit_mode_to_string(inhibitor->mode)),
                                          (uint32_t) inhibitor->uid,
                                          (uint32_t) inhibitor->pid.pid);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int manager_choose_session_id(
                Manager *m,
                const PidRef *leader,
                char **ret_id) {

        int r;

        assert(m);
        assert(pidref_is_set(leader));
        assert(ret_id);

        /* Try to keep our session IDs and the audit session IDs in sync */
        _cleanup_free_ char *id = NULL;
        uint32_t audit_id = AUDIT_SESSION_INVALID;
        r = audit_session_from_pid(leader, &audit_id);
        if (r < 0) {
                if (r != -ENODATA)
                        log_debug_errno(r, "Failed to read audit session ID of process " PID_FMT ", ignoring: %m", leader->pid);
        } else {
                if (asprintf(&id, "%"PRIu32, audit_id) < 0)
                        return -ENOMEM;

                /* Wut? There's already a session by this name and we didn't find it above? Weird, then let's
                 * not trust the audit data and let's better register a new ID */
                if (hashmap_contains(m->sessions, id)) {
                        log_warning("Existing logind session ID %s used by new audit session, ignoring.", id);
                        id = mfree(id);
                }
        }

        if (!id)
                do {
                        id = mfree(id);

                        if (asprintf(&id, "c%" PRIu64, ++m->session_counter) < 0)
                                return -ENOMEM;

                } while (hashmap_contains(m->sessions, id));

        /* The generated names should not clash with 'auto' or 'self' */
        assert(!session_is_self(id));
        assert(!session_is_auto(id));

        *ret_id = TAKE_PTR(id);
        return 0;
}

int manager_create_session(
                Manager *m,
                uid_t uid,
                PidRef *leader, /* consumed */
                const char *service,
                SessionType type,
                SessionClass class,
                const char *desktop,
                Seat *seat,
                unsigned vtnr,
                const char *tty,
                const char *display,
                bool remote,
                const char *remote_user,
                const char *remote_host,
                char * const *extra_device_access,
                Session **ret_session) {

        bool mangle_class = false;
        int r;

        assert(m);
        assert(uid_is_valid(uid));
        assert(pidref_is_set(leader));
        assert(ret_session);

        /* Returns:
         *    -EBUSY         → client is already in a session
         *    -EADDRNOTAVAIL → VT is already taken
         *    -EUSERS        → limit of sessions reached
         */

        if (type == _SESSION_TYPE_INVALID) {
                if (!isempty(display))
                        type = SESSION_X11;
                else if (!isempty(tty))
                        type = SESSION_TTY;
                else
                        type = SESSION_UNSPECIFIED;
        }

        if (class == _SESSION_CLASS_INVALID) {
                if (type == SESSION_UNSPECIFIED)
                        class = SESSION_BACKGROUND;
                else
                        class = SESSION_USER;

                /* If we determined the class automatically, then let's later potentially change it to early
                 * or light flavours, once we learn the disposition of the user */
                mangle_class = true;
        }

        /* Check if we are already in a logind session, and if so refuse. */
        r = manager_get_session_by_pidref(m, leader, /* ret= */ NULL);
        if (r < 0)
                return log_debug_errno(
                                r,
                                "Failed to check if process " PID_FMT " is already in a session: %m",
                                leader->pid);
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Client is already in a session.");

        /* Old gdm and lightdm start the user-session on the same VT as the greeter session. But they destroy
         * the greeter session after the user-session and want the user-session to take over the VT. We need
         * to support this for backwards-compatibility, so make sure we allow new sessions on a VT that a
         * greeter is running on. Furthermore, to allow re-logins, we have to allow a greeter to take over a
         * used VT for the exact same reasons. */
        if (class != SESSION_GREETER &&
            vtnr > 0 &&
            vtnr < MALLOC_ELEMENTSOF(m->seat0->positions) &&
            m->seat0->positions[vtnr] &&
            m->seat0->positions[vtnr]->class != SESSION_GREETER)
                return log_debug_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL), "VT already occupied by a session.");

        if (hashmap_size(m->sessions) >= m->sessions_max)
                return log_debug_errno(SYNTHETIC_ERRNO(EUSERS), "Maximum number of sessions (%" PRIu64 ") reached, refusing further sessions.", m->sessions_max);

        _cleanup_free_ char *id = NULL;
        r = manager_choose_session_id(m, leader, &id);
        if (r < 0)
                return r;

        /* If we are not watching utmp already, try again */
        manager_reconnect_utmp(m);

        User *user = NULL;
        Session *session = NULL;

        r = manager_add_user_by_uid(m, uid, &user);
        if (r < 0)
                goto fail;

        /* If we picked the session class on our own, and the user is not a regular one, and the session is
         * not a graphical one then do not pull in session manager by default. For root make a special
         * exception: for TTY logins leave the service manager on, but relax the /run/nologin
         * restrictions. */
        if (mangle_class &&
            IN_SET(user_record_disposition(user->user_record), USER_INTRINSIC, USER_SYSTEM, USER_DYNAMIC)) {

                if (class == SESSION_USER) {
                        if (user_record_is_root(user->user_record))
                                class = SESSION_USER_EARLY;
                        else if (SESSION_TYPE_IS_GRAPHICAL(type))
                                class = SESSION_USER;
                        else
                                class = SESSION_USER_LIGHT;

                } else if (class == SESSION_BACKGROUND)
                        class = SESSION_BACKGROUND_LIGHT;
        }

        r = manager_add_session(m, id, &session);
        if (r < 0)
                goto fail;

        session_set_user(session, user);
        r = session_set_leader_consume(session, TAKE_PIDREF(*leader));
        if (r < 0)
                goto fail;

        session->original_type = session->type = type;
        session->remote = remote;
        session->vtnr = vtnr;
        session->class = class;

        /* Once the first session that is of a pinning class shows up we'll change the GC mode for the user
         * from USER_GC_BY_ANY to USER_GC_BY_PIN, so that the user goes away once the last pinning session
         * goes away. Background: we want that user@.service – when started manually – remains around (which
         * itself is a non-pinning session), but gets stopped when the last pinning session goes away. */

        if (SESSION_CLASS_PIN_USER(class))
                user->gc_mode = USER_GC_BY_PIN;

        if (!isempty(tty)) {
                r = strdup_to(&session->tty, tty);
                if (r < 0)
                        goto fail;

                session->tty_validity = TTY_FROM_PAM;
        }

        if (!isempty(display)) {
                r = strdup_to(&session->display, display);
                if (r < 0)
                        goto fail;
        }

        if (!isempty(remote_user)) {
                r = strdup_to(&session->remote_user, remote_user);
                if (r < 0)
                        goto fail;
        }

        if (!isempty(remote_host)) {
                r = strdup_to(&session->remote_host, remote_host);
                if (r < 0)
                        goto fail;
        }

        if (!isempty(service)) {
                r = strdup_to(&session->service, service);
                if (r < 0)
                        goto fail;
        }

        if (!isempty(desktop)) {
                r = strdup_to(&session->desktop, desktop);
                if (r < 0)
                        goto fail;
        }

        r = strv_copy_unless_empty(extra_device_access, &session->extra_device_access);
        if (r < 0)
                goto fail;

        if (seat) {
                r = seat_attach_session(seat, session);
                if (r < 0)
                        goto fail;
        }

        *ret_session = session;
        return 0;

fail:
        if (session)
                session_add_to_gc_queue(session);

        if (user)
                user_add_to_gc_queue(user);

        return r;
}

static int manager_create_session_by_bus(
                Manager *m,
                sd_bus_message *message,
                sd_bus_error *error,
                uid_t uid,
                pid_t leader_pid,
                int leader_pidfd,
                const char *service,
                const char *type,
                const char *class,
                const char *desktop,
                const char *cseat,
                uint32_t vtnr,
                const char *tty,
                const char *display,
                int remote,
                const char *remote_user,
                const char *remote_host,
                uint64_t flags) {

        int r;

        assert(m);
        assert(message);

        if (!uid_is_valid(uid))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid UID");

        if (flags != 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Flags must be zero.");

        _cleanup_(pidref_done) PidRef leader = PIDREF_NULL;
        if (leader_pidfd >= 0)
                r = pidref_set_pidfd(&leader, leader_pidfd);
        else if (leader_pid == 0)
                r = bus_query_sender_pidref(message, &leader);
        else {
                if (leader_pid < 0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Leader PID is not valid");

                r = pidref_set_pid(&leader, leader_pid);
        }
        if (r < 0)
                return r;

        if (leader.pid == 1 || pidref_is_self(&leader))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid leader PID");

        if (leader.fd < 0)
                return sd_bus_error_set_errnof(error, EUNATCH, "Leader PIDFD not available");

        SessionType t;
        if (isempty(type))
                t = _SESSION_TYPE_INVALID;
        else {
                t = session_type_from_string(type);
                if (t < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Invalid session type %s", type);
        }

        SessionClass c;
        if (isempty(class))
                c = _SESSION_CLASS_INVALID;
        else {
                c = session_class_from_string(class);
                if (c < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Invalid session class %s", class);
                if (c == SESSION_NONE)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Refusing session class %s", class);
        }

        if (isempty(desktop))
                desktop = NULL;
        else {
                if (!string_is_safe(desktop))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Invalid desktop string %s", desktop);
        }

        Seat *seat = NULL;
        if (isempty(cseat))
                seat = NULL;
        else {
                seat = hashmap_get(m->seats, cseat);
                if (!seat)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_SEAT,
                                                 "No seat '%s' known", cseat);
        }

        if (isempty(tty))
                tty = NULL;
        else if (tty_is_vc(tty)) {
                int v;

                if (!seat)
                        seat = m->seat0;
                else if (seat != m->seat0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "TTY %s is virtual console but seat %s is not seat0", tty, seat->id);

                v = vtnr_from_tty(tty);
                if (v <= 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "Cannot determine VT number from virtual console TTY %s", tty);

                if (vtnr == 0)
                        vtnr = (uint32_t) v;
                else if (vtnr != (uint32_t) v)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                "Specified TTY and VT number do not match");

        } else if (tty_is_console(tty)) {

                if (!seat)
                        seat = m->seat0;
                else if (seat != m->seat0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                "Console TTY specified but seat is not seat0");

                if (vtnr != 0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                "Console TTY specified but VT number is not 0");
        }

        if (seat) {
                if (seat_has_vts(seat)) {
                        if (!vtnr_is_valid(vtnr))
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                        "VT number out of range");
                } else {
                        if (vtnr != 0)
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                        "Seat has no VTs but VT number not 0");
                }
        }

        Session *session;
        r = manager_create_session(
                        m,
                        uid,
                        &leader,
                        service,
                        t,
                        c,
                        desktop,
                        seat,
                        vtnr,
                        tty,
                        display,
                        remote,
                        remote_user,
                        remote_host,
                        /* extra_device_access= */ NULL,
                        &session);
        if (r == -EBUSY)
                return sd_bus_error_set(error, BUS_ERROR_SESSION_BUSY, "Already running in a session or user slice");
        if (r == -EADDRNOTAVAIL)
                return sd_bus_error_set(error, BUS_ERROR_SESSION_BUSY, "Virtual terminal already occupied by a session");
        if (r == -EUSERS)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED, "Maximum number of sessions (%" PRIu64 ") reached, refusing further sessions.", m->sessions_max);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(message, 'a', "(sv)");
        if (r < 0)
                goto fail;
        r = session_start(session, message, error);
        if (r < 0)
                goto fail;
        r = sd_bus_message_exit_container(message);
        if (r < 0)
                goto fail;

        session->create_message = sd_bus_message_ref(message);

        /* Now call into session_send_create_reply(), which will reply to this method call for us. Or it
         * won't – in case we just spawned a session scope and/or user service manager, and they aren't ready
         * yet. We'll call session_create_reply() again once the session scope or the user service manager is
         * ready, where the function will check again if a reply is then ready to be sent, and then do so if
         * all is complete - or wait again. */
        r = session_send_create_reply(session, /* error= */ NULL);
        if (r < 0)
                goto fail;

        return 1;

fail:
        if (session)
                session_add_to_gc_queue(session);

        return r;
}

static int method_create_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *service, *type, *class, *cseat, *tty, *display, *remote_user, *remote_host, *desktop;
        pid_t leader_pid;
        uint32_t vtnr;
        uid_t uid;
        int remote, r;

        assert(message);

        assert_cc(sizeof(pid_t) == sizeof(uint32_t));
        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        r = sd_bus_message_read(
                        message,
                        "uusssssussbss",
                        &uid,
                        &leader_pid,
                        &service,
                        &type,
                        &class,
                        &desktop,
                        &cseat,
                        &vtnr,
                        &tty,
                        &display,
                        &remote,
                        &remote_user,
                        &remote_host);
        if (r < 0)
                return r;

        return manager_create_session_by_bus(
                        userdata,
                        message,
                        error,
                        uid,
                        leader_pid,
                        /* leader_pidfd= */ -EBADF,
                        service,
                        type,
                        class,
                        desktop,
                        cseat,
                        vtnr,
                        tty,
                        display,
                        remote,
                        remote_user,
                        remote_host,
                        /* flags= */ 0);
}

static int method_create_session_pidfd(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *service, *type, *class, *cseat, *tty, *display, *remote_user, *remote_host, *desktop;
        uint64_t flags;
        uint32_t vtnr;
        uid_t uid;
        int leader_fd = -EBADF, remote, r;

        r = sd_bus_message_read(
                        message,
                        "uhsssssussbsst",
                        &uid,
                        &leader_fd,
                        &service,
                        &type,
                        &class,
                        &desktop,
                        &cseat,
                        &vtnr,
                        &tty,
                        &display,
                        &remote,
                        &remote_user,
                        &remote_host,
                        &flags);
        if (r < 0)
                return r;

        return manager_create_session_by_bus(
                        userdata,
                        message,
                        error,
                        uid,
                        /* leader_pid= */ 0,
                        leader_fd,
                        service,
                        type,
                        class,
                        desktop,
                        cseat,
                        vtnr,
                        tty,
                        display,
                        remote,
                        remote_user,
                        remote_host,
                        flags);
}

static int method_release_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Session *session, *sender_session;
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        r = get_sender_session(m, message, /* consult_display= */ false, error, &sender_session);
        if (r < 0)
                return r;

        if (session != sender_session)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED,
                                        "Refused to release session, since it doesn't match the one of the client");

        r = session_release(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_activate_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        /* PolicyKit is done by bus_session_method_activate() */

        return bus_session_method_activate(message, session, error);
}

static int method_activate_session_on_seat(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *session_name, *seat_name;
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        Seat *seat;
        int r;

        assert(message);

        /* Same as ActivateSession() but refuses to work if the seat doesn't match */

        r = sd_bus_message_read(message, "ss", &session_name, &seat_name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, session_name, error, &session);
        if (r < 0)
                return r;

        r = manager_get_seat_from_creds(m, message, seat_name, error, &seat);
        if (r < 0)
                return r;

        if (session->seat != seat)
                return sd_bus_error_setf(error, BUS_ERROR_SESSION_NOT_ON_SEAT,
                                         "Session %s not on seat %s", session_name, seat_name);

        r = check_polkit_chvt(message, m, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_lock_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        const char *name;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_lock(message, session, error);
}

static int method_lock_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.lock-sessions",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_send_lock_all(m, streq(sd_bus_message_get_member(message), "LockSessions"));
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_kill_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *name;
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_kill(message, session, error);
}

static int method_kill_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        uint32_t uid;
        User *user;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        r = manager_get_user_from_creds(m, message, uid, error, &user);
        if (r < 0)
                return r;

        return bus_user_method_kill(message, user, error);
}

static int method_terminate_session(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Session *session;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_session_from_creds(m, message, name, error, &session);
        if (r < 0)
                return r;

        return bus_session_method_terminate(message, session, error);
}

static int method_terminate_user(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        uint32_t uid;
        User *user;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;

        r = manager_get_user_from_creds(m, message, uid, error, &user);
        if (r < 0)
                return r;

        return bus_user_method_terminate(message, user, error);
}

static int method_terminate_seat(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Seat *seat;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0)
                return r;

        r = manager_get_seat_from_creds(m, message, name, error, &seat);
        if (r < 0)
                return r;

        return bus_seat_method_terminate(message, seat, error);
}

static int method_set_user_linger(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uint32_t uid, auth_uid;
        int r, enable, interactive;

        assert(message);

        r = sd_bus_message_read(message, "ubb", &uid, &enable, &interactive);
        if (r < 0)
                return r;

        r = sd_bus_query_sender_creds(message,
                                      SD_BUS_CREDS_EUID|SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT,
                                      &creds);
        if (r < 0)
                return r;

        if (!uid_is_valid(uid)) {
                /* Note that we get the owner UID of the session or user unit, not the actual client UID here! */
                r = sd_bus_creds_get_owner_uid(creds, &uid);
                if (r < 0)
                        return r;
        }

        /* owner_uid is racy, so for authorization we must use euid */
        r = sd_bus_creds_get_euid(creds, &auth_uid);
        if (r < 0)
                return r;

        _cleanup_free_ struct passwd *pw = NULL;

        r = getpwuid_malloc(uid, &pw);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async_full(
                        message,
                        uid == auth_uid ? "org.freedesktop.login1.set-self-linger" :
                                          "org.freedesktop.login1.set-user-linger",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        (void) mkdir_p_label("/var/lib/systemd", 0755);
        r = mkdir_safe_label("/var/lib/systemd/linger", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return r;

        _cleanup_free_ char *escaped = NULL;
        const char *path;
        User *u;

        escaped = cescape(pw->pw_name);
        if (!escaped)
                return -ENOMEM;

        path = strjoina("/var/lib/systemd/linger/", escaped);

        if (enable) {
                r = touch(path);
                if (r < 0)
                        return r;

                if (manager_add_user_by_uid(m, uid, &u) >= 0) {
                        (void) user_send_changed(u, "Linger");
                        r = user_start(u);
                        if (r < 0) {
                                user_add_to_gc_queue(u);
                                return r;
                        }
                }

        } else {
                r = unlink(path);
                if (r < 0 && errno != ENOENT)
                        return -errno;

                u = hashmap_get(m->users, UID_TO_PTR(uid));
                if (u) {
                        /* Make sure that disabling lingering will terminate the user tracking if no sessions pin it. */
                        u->gc_mode = USER_GC_BY_PIN;
                        user_add_to_gc_queue(u);
                        (void) user_send_changed(u, "Linger");
                }
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int trigger_device(Manager *m, sd_device *parent) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(m);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        if (parent) {
                r = sd_device_enumerator_add_match_parent(e, parent);
                if (r < 0)
                        return r;
        }

        FOREACH_DEVICE(e, d) {
                r = sd_device_trigger(d, SD_DEVICE_CHANGE);
                if (r < 0)
                        log_device_debug_errno(d, r, "Failed to trigger device, ignoring: %m");
        }

        return 0;
}

static int attach_device(Manager *m, const char *seat, const char *sysfs, sd_bus_error *error) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *file = NULL;
        const char *id_for_seat;
        int r;

        assert(m);
        assert(seat);
        assert(sysfs);

        r = sd_device_new_from_syspath(&d, sysfs);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to open device '%s': %m", sysfs);

        if (sd_device_has_current_tag(d, "seat") <= 0)
                return sd_bus_error_set_errnof(error, ENODEV, "Device '%s' lacks 'seat' udev tag.", sysfs);

        if (sd_device_get_property_value(d, "ID_FOR_SEAT", &id_for_seat) < 0)
                return sd_bus_error_set_errnof(error, ENODEV, "Device '%s' lacks 'ID_FOR_SEAT' udev property.", sysfs);

        if (asprintf(&file, "/etc/udev/rules.d/72-seat-%s.rules", id_for_seat) < 0)
                return -ENOMEM;

        r = write_string_filef(
                        file,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755|WRITE_STRING_FILE_LABEL,
                        "TAG==\"seat\", ENV{ID_FOR_SEAT}==\"%s\", ENV{ID_SEAT}=\"%s\"", id_for_seat, seat);
        if (r < 0)
                return r;

        return trigger_device(m, d);
}

static int flush_devices(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;

        assert(m);

        d = opendir("/etc/udev/rules.d");
        if (!d) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open %s: %m", "/etc/udev/rules.d");
        } else
                FOREACH_DIRENT_ALL(de, d, break) {
                        if (!dirent_is_file(de))
                                continue;

                        if (!startswith(de->d_name, "72-seat-"))
                                continue;

                        if (!endswith(de->d_name, ".rules"))
                                continue;

                        if (unlinkat(dirfd(d), de->d_name, 0) < 0)
                                log_warning_errno(errno, "Failed to unlink %s: %m", de->d_name);
                }

        return trigger_device(m, NULL);
}

static int method_attach_device(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *sysfs, *seat;
        Manager *m = ASSERT_PTR(userdata);
        int interactive, r;

        assert(message);

        r = sd_bus_message_read(message, "ssb", &seat, &sysfs, &interactive);
        if (r < 0)
                return r;

        if (!path_is_normalized(sysfs))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not normalized", sysfs);
        if (!path_startswith(sysfs, "/sys"))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Path %s is not in /sys", sysfs);

        if (seat_is_self(seat) || seat_is_auto(seat)) {
                Seat *found;

                r = manager_get_seat_from_creds(m, message, seat, error, &found);
                if (r < 0)
                        return r;

                seat = found->id;

        } else if (!seat_name_is_valid(seat)) /* Note that a seat does not have to exist yet for this operation to succeed */
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Seat name %s is not valid", seat);

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.attach-device",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = attach_device(m, seat, sysfs, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_flush_devices(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int interactive, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &interactive);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.flush-devices",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = flush_devices(m);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int have_multiple_sessions(
                Manager *m,
                uid_t uid) {

        Session *session;

        assert(m);

        /* Check for other users' sessions. Greeter sessions do not
         * count, and non-login sessions do not count either. */
        HASHMAP_FOREACH(session, m->sessions)
                if (SESSION_CLASS_IS_INHIBITOR_LIKE(session->class) &&
                    session->user->user_record->uid != uid)
                        return true;

        return false;
}

static int bus_manager_log_shutdown(
                Manager *m,
                const HandleActionData *a) {
        assert(m);
        assert(a);

        const char *message = a->message ?: "System is shutting down";
        const char *log_verb = a->log_verb ? strjoina("SHUTDOWN=", a->log_verb) : NULL;

        return log_struct(LOG_NOTICE,
                          LOG_ITEM("MESSAGE_ID=%s", a->message_id ?: SD_MESSAGE_SHUTDOWN_STR),
                          LOG_MESSAGE("%s%s%s%s.",
                                      message,
                                      m->wall_message ? " (" : "",
                                      strempty(m->wall_message),
                                      m->wall_message ? ")" : ""),
                          log_verb);
}

static int lid_switch_ignore_handler(sd_event_source *e, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(e);

        m->lid_switch_ignore_event_source = sd_event_source_unref(m->lid_switch_ignore_event_source);
        return 0;
}

int manager_set_lid_switch_ignore(Manager *m, usec_t until) {
        int r;

        assert(m);

        if (until <= now(CLOCK_MONOTONIC))
                return 0;

        /* We want to ignore the lid switch for a while after each
         * suspend, and after boot-up. Hence let's install a timer for
         * this. As long as the event source exists we ignore the lid
         * switch. */

        if (m->lid_switch_ignore_event_source) {
                usec_t u;

                r = sd_event_source_get_time(m->lid_switch_ignore_event_source, &u);
                if (r < 0)
                        return r;

                if (until <= u)
                        return 0;

                r = sd_event_source_set_time(m->lid_switch_ignore_event_source, until);
        } else
                r = sd_event_add_time(
                                m->event,
                                &m->lid_switch_ignore_event_source,
                                CLOCK_MONOTONIC,
                                until, 0,
                                lid_switch_ignore_handler, m);

        return r;
}

static int send_prepare_for(Manager *m, const HandleActionData *a, bool _active) {
        int k = 0, r, active = _active;

        assert(m);
        assert(a);

        /* Only sleep/shutdown actions emit a signal */
        if (a->inhibit_what < 0)
                return 0;

        assert(IN_SET(a->inhibit_what, INHIBIT_SHUTDOWN, INHIBIT_SLEEP));

        /* We need to send both old and new signal for backward compatibility. The newer one allows clients
         * to know which type of reboot is going to happen, as they might be doing different actions (e.g.:
         * on soft-reboot), and it is sent first, so that clients know that if they receive the old one
         * first then they don't have to wait for the new one, as it means it's not supported. So, do not
         * change the order here, as it is an API. */
        if (a->inhibit_what == INHIBIT_SHUTDOWN) {
                k = sd_bus_emit_signal(m->bus,
                                       "/org/freedesktop/login1",
                                       "org.freedesktop.login1.Manager",
                                       "PrepareForShutdownWithMetadata",
                                       "ba{sv}",
                                       active,
                                       1,
                                       "type",
                                       "s",
                                       handle_action_to_string(a->handle));
                if (k < 0)
                        log_debug_errno(k, "Failed to emit PrepareForShutdownWithMetadata(): %m");
        }

        r = sd_bus_emit_signal(m->bus,
                               "/org/freedesktop/login1",
                               "org.freedesktop.login1.Manager",
                               a->inhibit_what == INHIBIT_SHUTDOWN ? "PrepareForShutdown" : "PrepareForSleep",
                               "b",
                               active);
        if (r < 0)
                log_debug_errno(r, "Failed to emit PrepareForShutdown(): %m");

        return RET_GATHER(k, r);
}

static int strdup_job(sd_bus_message *reply, char **ret) {
        const char *j;
        char *job;
        int r;

        assert(reply);
        assert(ret);

        r = sd_bus_message_read_basic(reply, 'o', &j);
        if (r < 0)
                return r;

        job = strdup(j);
        if (!job)
                return -ENOMEM;

        *ret = job;
        return 0;
}

static int execute_shutdown_or_sleep(
                Manager *m,
                const HandleActionData *a,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(m);
        assert(!m->action_job);
        assert(a);

        if (a->inhibit_what == INHIBIT_SHUTDOWN)
                bus_manager_log_shutdown(m, a);

        r = bus_call_method(
                        m->bus,
                        bus_systemd_mgr,
                        "StartUnit",
                        error,
                        &reply,
                        "ss", a->target, "replace-irreversibly");
        if (r < 0)
                goto fail;

        r = strdup_job(reply, &m->action_job);
        if (r < 0)
                goto fail;

        /* Save the action to prevent another request of shutdown or friends before the current action being
         * finished. See method_do_shutdown_or_sleep(). This is also used in match_job_removed() to log what
         * kind of action is finished. */
        m->delayed_action = a;

        /* Make sure the lid switch is ignored for a while. */
        manager_set_lid_switch_ignore(m, usec_add(now(CLOCK_MONOTONIC), m->holdoff_timeout_usec));

        return 0;

fail:
        /* Tell people that they now may take a lock again. */
        (void) send_prepare_for(m, a, false);

        return r;
}

int manager_dispatch_delayed(Manager *manager, bool timeout) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Inhibitor *offending = NULL;
        int r;

        assert(manager);

        if (!manager->delayed_action || manager->action_job)
                return 0;

        if (manager_is_inhibited(
                            manager,
                            manager->delayed_action->inhibit_what,
                            /* since= */ NULL,
                            MANAGER_IS_INHIBITED_CHECK_DELAY,
                            UID_INVALID,
                            &offending)) {
                if (!timeout)
                        return 0;

                _cleanup_free_ char *comm = NULL, *u = NULL;
                (void) pidref_get_comm(&offending->pid, &comm);
                u = uid_to_name(offending->uid);

                log_notice("Delay lock is active (UID "UID_FMT"/%s, PID "PID_FMT"/%s) but inhibitor timeout is reached.",
                           offending->uid, strna(u),
                           offending->pid.pid, strna(comm));
        }

        /* Actually do the operation */
        r = execute_shutdown_or_sleep(manager, manager->delayed_action, &error);
        if (r < 0) {
                log_warning("Error during inhibitor-delayed operation (already returned success to client): %s",
                            bus_error_message(&error, r));

                manager->delayed_action = NULL;
        }

        return 1; /* We did some work. */
}

static int manager_inhibit_timeout_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        Manager *manager = ASSERT_PTR(userdata);

        assert(manager->inhibit_timeout_source == s);

        return manager_dispatch_delayed(manager, true);
}

static int delay_shutdown_or_sleep(
                Manager *m,
                const HandleActionData *a) {

        int r;

        assert(m);
        assert(a);

        r = event_reset_time_relative(
                        m->event, &m->inhibit_timeout_source,
                        CLOCK_MONOTONIC, m->inhibit_delay_max, /* accuracy= */ 0,
                        manager_inhibit_timeout_handler, m,
                        /* priority= */ 0, "inhibit-timeout", /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to reset timer event source for inhibit timeout: %m");

        m->delayed_action = a;

        return 0;
}

static void cancel_delayed_action(Manager *m) {
        assert(m);

        (void) sd_event_source_set_enabled(m->inhibit_timeout_source, SD_EVENT_OFF);

        /* When m->action_job is NULL, the delayed action has not been triggered yet. Let's clear it to
         * accept later shutdown and friends.
         *
         * When m->action_job is non-NULL, the delayed action has been already triggered, and now we are
         * waiting for the job being finished. In match_job_removed(), the triggered action will be used.
         * Hence, do not clear it. */
        if (!m->action_job)
                m->delayed_action = NULL;
}

int bus_manager_shutdown_or_sleep_now_or_later(
                Manager *m,
                const HandleActionData *a,
                sd_bus_error *error) {

        _cleanup_free_ char *load_state = NULL;
        bool delayed;
        int r;

        assert(m);
        assert(a);
        assert(!m->action_job);

        r = unit_load_state(m->bus, a->target, &load_state);
        if (r < 0)
                return r;

        if (!streq(load_state, "loaded"))
                return log_notice_errno(SYNTHETIC_ERRNO(EACCES),
                                        "Unit %s is %s, refusing operation.",
                                        a->target, load_state);

        /* Tell everybody to prepare for shutdown/sleep */
        (void) send_prepare_for(m, a, true);

        delayed =
                m->inhibit_delay_max > 0 &&
                a->inhibit_what >= 0 &&
                manager_is_inhibited(m, a->inhibit_what, NULL, MANAGER_IS_INHIBITED_CHECK_DELAY, UID_INVALID, NULL);

        if (delayed)
                /* Shutdown is delayed, keep in mind what we
                 * want to do, and start a timeout */
                r = delay_shutdown_or_sleep(m, a);
        else
                /* Shutdown is not delayed, execute it
                 * immediately */
                r = execute_shutdown_or_sleep(m, a, error);

        return r;
}

static int verify_shutdown_creds(
                Manager *m,
                sd_bus_message *message,
                const HandleActionData *a,
                uint64_t flags,
                sd_bus_error *error) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        bool multiple_sessions, blocked, interactive;
        _unused_ bool error_or_denial = false;
        Inhibitor *offending = NULL;
        uid_t uid;
        int r;

        assert(m);
        assert(a);
        assert(message);

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, a->inhibit_what, NULL, /* flags= */ 0, uid, &offending);
        interactive = flags & SD_LOGIND_INTERACTIVE;

        if (multiple_sessions) {
                r = bus_verify_polkit_async_full(
                                message,
                                a->polkit_action_multiple_sessions,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                                &m->polkit_registry,
                                error);
                if (r < 0) {
                        /* If we get -EBUSY, it means a polkit decision was made, but not for
                         * this action in particular. Assuming we are blocked on inhibitors,
                         * ignore that error and allow the decision to be revealed below. */
                        if (blocked && r == -EBUSY)
                                error_or_denial = true;
                        else
                                return r;
                }
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (blocked) {
                PolkitFlags polkit_flags = 0;

                /* With a strong inhibitor, if the skip flag is not set, reject outright.
                 * With a weak inhibitor, if root is asking and the root flag is set, reject outright.
                 * All else, check polkit first. */
                if (!FLAGS_SET(flags, SD_LOGIND_SKIP_INHIBITORS) &&
                    (offending->mode != INHIBIT_BLOCK_WEAK ||
                     (uid == 0 && FLAGS_SET(flags, SD_LOGIND_ROOT_CHECK_INHIBITORS))))
                        return sd_bus_error_set(error, BUS_ERROR_BLOCKED_BY_INHIBITOR_LOCK,
                                                "Operation denied due to active block inhibitor");

                /* We want to always ask here, even for root, to only allow bypassing if explicitly allowed
                 * by polkit, unless a weak blocker is used, in which case it will be authorized. */
                if (offending->mode != INHIBIT_BLOCK_WEAK)
                        polkit_flags |= POLKIT_ALWAYS_QUERY;

                if (interactive)
                        polkit_flags |= POLKIT_ALLOW_INTERACTIVE;

                r = bus_verify_polkit_async_full(
                                message,
                                a->polkit_action_ignore_inhibit,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                polkit_flags,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (!multiple_sessions && !blocked) {
                r = bus_verify_polkit_async_full(
                                message,
                                a->polkit_action,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                                &m->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        /* If error_or_denial was set above, it means that a polkit denial or
         * error was deferred for a future call to bus_verify_polkit_async_full()
         * to catch. In any case, it also means that the payload guarded by
         * these polkit calls should never be executed, and hence we should
         * never reach this point. */
        assert(!error_or_denial);

        return 0;
}

static int setup_wall_message_timer(Manager *m, sd_bus_message* message) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        int r;

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_TTY|SD_BUS_CREDS_UID, &creds);
        if (r >= 0) {
                const char *tty = NULL;

                (void) sd_bus_creds_get_uid(creds, &m->scheduled_shutdown_uid);
                (void) sd_bus_creds_get_tty(creds, &tty);

                r = free_and_strdup(&m->scheduled_shutdown_tty, tty);
                if (r < 0)
                        return log_oom();
        }

        r = manager_setup_wall_message_timer(m);
        if (r < 0)
                return r;

        return 0;
}

static int method_do_shutdown_or_sleep(
                Manager *m,
                sd_bus_message *message,
                HandleAction action,
                bool with_flags,
                sd_bus_error *error) {

        uint64_t flags;
        int r;

        assert(m);
        assert(message);
        assert(HANDLE_ACTION_IS_SHUTDOWN(action) || HANDLE_ACTION_IS_SLEEP(action));

        if (with_flags) {
                /* New style method: with flags parameter (and interactive bool in the bus message header) */
                r = sd_bus_message_read(message, "t", &flags);
                if (r < 0)
                        return r;
                if ((flags & ~SD_LOGIND_SHUTDOWN_AND_SLEEP_FLAGS_PUBLIC) != 0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                "Invalid flags parameter");

                if (FLAGS_SET(flags, (SD_LOGIND_REBOOT_VIA_KEXEC|SD_LOGIND_SOFT_REBOOT)))
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                "Both reboot via kexec and soft reboot selected, which is not supported");

                if (action != HANDLE_REBOOT) {
                        if (FLAGS_SET(flags, SD_LOGIND_REBOOT_VIA_KEXEC))
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                        "Reboot via kexec option is only applicable with reboot operations");
                        if (flags & (SD_LOGIND_SOFT_REBOOT|SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP))
                                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                                        "Soft reboot option is only applicable with reboot operations");
                }
        } else {
                /* Old style method: no flags parameter, but interactive bool passed as boolean in
                 * payload. Let's convert this argument to the new-style flags parameter for our internal
                 * use. */
                int interactive;

                r = sd_bus_message_read(message, "b", &interactive);
                if (r < 0)
                        return r;

                flags = interactive ? SD_LOGIND_INTERACTIVE : 0;
        }

        const HandleActionData *a = NULL;

        if (FLAGS_SET(flags, SD_LOGIND_SOFT_REBOOT) ||
            (FLAGS_SET(flags, SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP) && path_is_os_tree("/run/nextroot") > 0))
                a = handle_action_lookup(HANDLE_SOFT_REBOOT);
        else if (FLAGS_SET(flags, SD_LOGIND_REBOOT_VIA_KEXEC) && kexec_loaded())
                a = handle_action_lookup(HANDLE_KEXEC);

        if (action == HANDLE_SLEEP) {
                HandleAction selected;

                selected = handle_action_sleep_select(m);
                if (selected < 0)
                        return sd_bus_error_set(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                "None of the configured sleep operations are supported");

                assert_se(a = handle_action_lookup(selected));

        } else if (HANDLE_ACTION_IS_SLEEP(action)) {
                SleepSupport support;

                assert_se(a = handle_action_lookup(action));

                assert(a->sleep_operation >= 0);
                assert(a->sleep_operation < _SLEEP_OPERATION_MAX);

                r = sleep_supported_full(a->sleep_operation, &support);
                if (r < 0)
                        return r;
                if (r == 0)
                        switch (support) {

                        case SLEEP_DISABLED:
                                return sd_bus_error_setf(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                         "Sleep verb '%s' is disabled by config",
                                                         sleep_operation_to_string(a->sleep_operation));

                        case SLEEP_NOT_CONFIGURED:
                        case SLEEP_STATE_OR_MODE_NOT_SUPPORTED:
                        case SLEEP_ALARM_NOT_SUPPORTED:
                                return sd_bus_error_setf(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                         "Sleep verb '%s' is not configured or configuration is not supported by kernel",
                                                         sleep_operation_to_string(a->sleep_operation));

                        case SLEEP_RESUME_NOT_SUPPORTED:
                                return sd_bus_error_set(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                        "Not running on EFI and resume= is not set, or noresume is set. No available method to resume from hibernation");

                        case SLEEP_RESUME_DEVICE_MISSING:
                                return sd_bus_error_set(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                        "Specified resume device is missing or is not an active swap device");

                        case SLEEP_RESUME_MISCONFIGURED:
                                return sd_bus_error_set(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                        "Invalid resume config: resume= is not populated yet resume_offset= is");

                        case SLEEP_NOT_ENOUGH_SWAP_SPACE:
                                return sd_bus_error_set(error, BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,
                                                        "Not enough suitable swap space for hibernation available on compatible block devices and file systems");

                        default:
                                assert_not_reached();

                        }
        } else if (!a)
                assert_se(a = handle_action_lookup(action));

        r = verify_shutdown_creds(m, message, a, flags, error);
        if (r != 0)
                return r;

        if (m->delayed_action)
                return sd_bus_error_setf(error, BUS_ERROR_OPERATION_IN_PROGRESS,
                                         "Action %s already in progress, refusing requested %s operation.",
                                         handle_action_to_string(m->delayed_action->handle),
                                         handle_action_to_string(a->handle));

        /* reset case we're shorting a scheduled shutdown */
        m->unlink_nologin = false;
        reset_scheduled_shutdown(m);

        m->scheduled_shutdown_timeout = 0;
        m->scheduled_shutdown_action = action;

        (void) setup_wall_message_timer(m, message);

        r = bus_manager_shutdown_or_sleep_now_or_later(m, a, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_POWEROFF,
                        sd_bus_message_is_method_call(message, NULL, "PowerOffWithFlags"),
                        error);
}

static int method_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_REBOOT,
                        sd_bus_message_is_method_call(message, NULL, "RebootWithFlags"),
                        error);
}

static int method_halt(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_HALT,
                        sd_bus_message_is_method_call(message, NULL, "HaltWithFlags"),
                        error);
}

static int method_suspend(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_SUSPEND,
                        sd_bus_message_is_method_call(message, NULL, "SuspendWithFlags"),
                        error);
}

static int method_hibernate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_HIBERNATE,
                        sd_bus_message_is_method_call(message, NULL, "HibernateWithFlags"),
                        error);
}

static int method_hybrid_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_HYBRID_SLEEP,
                        sd_bus_message_is_method_call(message, NULL, "HybridSleepWithFlags"),
                        error);
}

static int method_suspend_then_hibernate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_SUSPEND_THEN_HIBERNATE,
                        sd_bus_message_is_method_call(message, NULL, "SuspendThenHibernateWithFlags"),
                        error);
}

static int method_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_do_shutdown_or_sleep(
                        m, message,
                        HANDLE_SLEEP,
                        /* with_flags= */ true,
                        error);
}

static int nologin_timeout_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        Manager *m = ASSERT_PTR(userdata);

        log_info("Creating /run/nologin, blocking further logins...");

        m->unlink_nologin =
                create_shutdown_run_nologin_or_warn() >= 0;

        return 0;
}

static usec_t nologin_timeout_usec(usec_t elapse) {
        /* Issue /run/nologin five minutes before shutdown */
        return LESS_BY(elapse, 5 * USEC_PER_MINUTE);
}

static void reset_scheduled_shutdown(Manager *m) {
        assert(m);

        m->scheduled_shutdown_timeout_source = sd_event_source_disable_unref(m->scheduled_shutdown_timeout_source);
        m->wall_message_timeout_source = sd_event_source_disable_unref(m->wall_message_timeout_source);
        m->nologin_timeout_source = sd_event_source_disable_unref(m->nologin_timeout_source);

        m->scheduled_shutdown_action = _HANDLE_ACTION_INVALID;
        m->scheduled_shutdown_timeout = USEC_INFINITY;
        m->scheduled_shutdown_uid = UID_INVALID;
        m->scheduled_shutdown_tty = mfree(m->scheduled_shutdown_tty);
        m->shutdown_dry_run = false;

        if (m->unlink_nologin) {
                (void) unlink_or_warn("/run/nologin");
                m->unlink_nologin = false;
        }

        (void) unlink(SHUTDOWN_SCHEDULE_FILE);

        manager_send_changed(m, "ScheduledShutdown");
}

static int update_schedule_file(Manager *m) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(m);
        assert(handle_action_valid(m->scheduled_shutdown_action));

        r = mkdir_parents_label(SHUTDOWN_SCHEDULE_FILE, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create shutdown subdirectory: %m");

        r = fopen_temporary(SHUTDOWN_SCHEDULE_FILE, &f, &temp_path);
        if (r < 0)
                return log_error_errno(r, "Failed to save information about scheduled shutdowns: %m");

        (void) fchmod(fileno(f), 0644);

        serialize_usec(f, "USEC", m->scheduled_shutdown_timeout);
        serialize_item_format(f, "WARN_WALL", "%s", one_zero(m->wall_messages));
        serialize_item_format(f, "MODE", "%s", handle_action_to_string(m->scheduled_shutdown_action));
        serialize_item_format(f, "UID", UID_FMT, m->scheduled_shutdown_uid);

        if (m->scheduled_shutdown_tty)
                serialize_item_format(f, "TTY", "%s", m->scheduled_shutdown_tty);

        if (!isempty(m->wall_message)) {
                r = serialize_item_escaped(f, "WALL_MESSAGE", m->wall_message);
                if (r < 0)
                        goto fail;
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, SHUTDOWN_SCHEDULE_FILE) < 0) {
                r = -errno;
                goto fail;
        }

        temp_path = mfree(temp_path);
        return 0;

fail:
        (void) unlink(SHUTDOWN_SCHEDULE_FILE);

        return log_error_errno(r, "Failed to write information about scheduled shutdowns: %m");
}

static int manager_scheduled_shutdown_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const HandleActionData *a;
        int r;

        assert_se(a = handle_action_lookup(m->scheduled_shutdown_action));

        /* Don't allow multiple jobs being executed at the same time */
        if (m->delayed_action) {
                r = log_error_errno(SYNTHETIC_ERRNO(EALREADY),
                                    "Scheduled shutdown to %s failed: shutdown or sleep operation already in progress.",
                                    a->target);
                goto error;
        }

        if (m->shutdown_dry_run) {
                /* We do not process delay inhibitors here.  Otherwise, we
                 * would have to be considered "in progress" (like the check
                 * above) for some seconds after our admin has seen the final
                 * wall message. */

                bus_manager_log_shutdown(m, a);
                log_info("Running in dry run, suppressing action.");
                reset_scheduled_shutdown(m);

                return 0;
        }

        r = bus_manager_shutdown_or_sleep_now_or_later(m, a, &error);
        if (r < 0) {
                log_error_errno(r, "Scheduled shutdown to %s failed: %m", a->target);
                goto error;
        }

        return 0;

error:
        reset_scheduled_shutdown(m);
        return r;
}

static int manager_setup_shutdown_timers(Manager* m) {
        int r;

        assert(m);

        r = event_reset_time(m->event, &m->scheduled_shutdown_timeout_source,
                             CLOCK_REALTIME,
                             m->scheduled_shutdown_timeout, 0,
                             manager_scheduled_shutdown_handler, m,
                             0, "scheduled-shutdown-timeout", true);
        if (r < 0)
                goto fail;

        r = event_reset_time(m->event, &m->nologin_timeout_source,
                             CLOCK_REALTIME,
                             nologin_timeout_usec(m->scheduled_shutdown_timeout), 0,
                             nologin_timeout_handler, m,
                             0, "nologin-timeout", true);
        if (r < 0)
                goto fail;

        return 0;

fail:
        m->scheduled_shutdown_timeout_source = sd_event_source_unref(m->scheduled_shutdown_timeout_source);
        m->nologin_timeout_source = sd_event_source_unref(m->nologin_timeout_source);

        return r;
}

void manager_load_scheduled_shutdown(Manager *m) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *usec = NULL,
               *warn_wall = NULL,
               *mode = NULL,
               *wall_message = NULL,
               *uid = NULL,
               *tty = NULL;
        int r;

        assert(m);

        r = parse_env_file(f, SHUTDOWN_SCHEDULE_FILE,
                           "USEC", &usec,
                           "WARN_WALL", &warn_wall,
                           "MODE", &mode,
                           "WALL_MESSAGE", &wall_message,
                           "UID", &uid,
                           "TTY", &tty);

        /* reset will delete the file */
        reset_scheduled_shutdown(m);

        if (r == -ENOENT)
                return;
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to parse " SHUTDOWN_SCHEDULE_FILE ": %m");

        HandleAction handle = handle_action_from_string(mode);
        if (handle < 0)
                return (void) log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse scheduled shutdown type: %s", mode);

        if (!usec)
                return (void) log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "USEC is required");
        if (deserialize_usec(usec, &m->scheduled_shutdown_timeout) < 0)
                return;

        /* assign parsed type only after we know usec is also valid */
        m->scheduled_shutdown_action = handle;

        if (warn_wall) {
                r = parse_boolean(warn_wall);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse enabling wall messages");
                else
                        m->wall_messages = r;
        }

        if (wall_message) {
                _cleanup_free_ char *unescaped = NULL;
                r = cunescape(wall_message, 0, &unescaped);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse wall message: %s", wall_message);
                else
                        free_and_replace(m->wall_message, unescaped);
        }

        if (uid) {
                r = parse_uid(uid, &m->scheduled_shutdown_uid);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse wall uid: %s", uid);
        }

        free_and_replace(m->scheduled_shutdown_tty, tty);

        r = manager_setup_shutdown_timers(m);
        if (r < 0)
                return reset_scheduled_shutdown(m);

        (void) manager_setup_wall_message_timer(m);
        (void) update_schedule_file(m);

        return;
}

static int method_schedule_shutdown(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        HandleAction handle;
        const HandleActionData *a;
        uint64_t elapse;
        char *type;
        int r;
        bool dry_run = false;

        assert(message);

        r = sd_bus_message_read(message, "st", &type, &elapse);
        if (r < 0)
                return r;

        if (startswith(type, "dry-")) {
                type += 4;
                dry_run = true;
        }

        handle = handle_action_from_string(type);
        if (!HANDLE_ACTION_IS_SHUTDOWN(handle))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unsupported shutdown type: %s", type);

        assert_se(a = handle_action_lookup(handle));
        assert(a->polkit_action);

        r = verify_shutdown_creds(m, message, a, 0, error);
        if (r != 0)
                return r;

        if (elapse == USEC_INFINITY) {
                if (m->maintenance_time) {
                        r = calendar_spec_next_usec(m->maintenance_time, now(CLOCK_REALTIME), &elapse);
                        if (r == -ENOENT)
                                return sd_bus_error_set(error,
                                                        BUS_ERROR_DESIGNATED_MAINTENANCE_TIME_NOT_SCHEDULED,
                                                        "No upcoming maintenance window scheduled");
                        if (r < 0)
                                return sd_bus_error_set_errnof(error, r,
                                                               "Failed to determine next maintenance window: %m");

                        log_info("Scheduled %s at maintenance window %s", type, FORMAT_TIMESTAMP(elapse));
                } else
                        /* the good old shutdown command uses one minute by default */
                        elapse = usec_add(now(CLOCK_REALTIME), USEC_PER_MINUTE);
        }

        m->scheduled_shutdown_action = handle;
        m->shutdown_dry_run = dry_run;
        m->scheduled_shutdown_timeout = elapse;

        r = manager_setup_shutdown_timers(m);
        if (r < 0)
                return r;

        r = setup_wall_message_timer(m, message);
        if (r >= 0)
                r = update_schedule_file(m);

        if (r < 0) {
                reset_scheduled_shutdown(m);
                return r;
        }

        manager_send_changed(m, "ScheduledShutdown");

        return sd_bus_reply_method_return(message, NULL);
}

static int method_cancel_scheduled_shutdown(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const HandleActionData *a;
        bool cancelled;
        int r;

        assert(message);

        cancelled = handle_action_valid(m->scheduled_shutdown_action) && m->scheduled_shutdown_action != HANDLE_IGNORE;
        if (!cancelled)
                return sd_bus_reply_method_return(message, "b", false);

        assert_se(a = handle_action_lookup(m->scheduled_shutdown_action));
        if (!a->polkit_action)
                return sd_bus_error_set(error, SD_BUS_ERROR_AUTH_FAILED, "Unsupported shutdown type");

        r = bus_verify_polkit_async(
                        message,
                        a->polkit_action,
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (m->wall_messages) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                const char *tty = NULL;
                uid_t uid = 0;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_AUGMENT|SD_BUS_CREDS_TTY|SD_BUS_CREDS_UID, &creds);
                if (r >= 0) {
                        (void) sd_bus_creds_get_uid(creds, &uid);
                        (void) sd_bus_creds_get_tty(creds, &tty);
                }

                _cleanup_free_ char *username = uid_to_name(uid);

                log_struct(LOG_INFO,
                           LOG_MESSAGE("System shutdown has been cancelled"),
                           LOG_ITEM("ACTION=%s", handle_action_to_string(a->handle)),
                           LOG_MESSAGE_ID(SD_MESSAGE_SHUTDOWN_CANCELED_STR),
                           username ? "OPERATOR=%s" : NULL, username);

                (void) wall("System shutdown has been cancelled",
                            username, tty, logind_wall_tty_filter, m);
        }

        cancel_delayed_action(m);
        reset_scheduled_shutdown(m);

        return sd_bus_reply_method_return(message, "b", true);
}

static int method_can_shutdown_or_sleep(
                Manager *m,
                sd_bus_message *message,
                HandleAction action,
                sd_bus_error *error) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        bool multiple_sessions, challenge, blocked, check_unit_state = true;
        const HandleActionData *a;
        uid_t uid;
        int r;

        assert(m);
        assert(message);
        assert(HANDLE_ACTION_IS_SHUTDOWN(action) || HANDLE_ACTION_IS_SLEEP(action));

        if (action == HANDLE_SLEEP) {
                HandleAction selected;

                selected = handle_action_sleep_select(m);
                if (selected < 0)
                        return sd_bus_reply_method_return(message, "s", "na");

                check_unit_state = false; /* Already handled by handle_action_sleep_select */

                assert_se(a = handle_action_lookup(selected));

        } else if (HANDLE_ACTION_IS_SLEEP(action)) {
                SleepSupport support;

                assert_se(a = handle_action_lookup(action));

                assert(a->sleep_operation >= 0);
                assert(a->sleep_operation < _SLEEP_OPERATION_MAX);

                r = sleep_supported_full(a->sleep_operation, &support);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_reply_method_return(message, "s", support == SLEEP_DISABLED ? "no" : "na");
        } else
                assert_se(a = handle_action_lookup(action));

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, a->inhibit_what, NULL, /* flags= */ 0, uid, NULL);

        if (check_unit_state && a->target) {
                _cleanup_free_ char *load_state = NULL;

                r = unit_load_state(m->bus, a->target, &load_state);
                if (r < 0)
                        return r;

                if (!streq(load_state, "loaded"))
                        return sd_bus_reply_method_return(message, "s", "no");
        }

        const char *result;
        r = bus_test_polkit(
                        message,
                        a->polkit_action,
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        &challenge,
                        error);
        if (r < 0)
                return r;
        if (r > 0)
                result = "yes";
        else if (challenge)
                result = "challenge";
        else
                result = "no";

        if (multiple_sessions) {
                r = bus_test_polkit(
                                message,
                                a->polkit_action_multiple_sessions,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                &challenge,
                                error);
                if (r < 0)
                        return r;

                if (r == 0) {
                        if (challenge) {
                                if (streq(result, "yes")) /* Avoid upgrading no -> challenge */
                                        result = "challenge";
                        } else
                                result = "no";
                }
        }

        if (blocked) {
                r = bus_test_polkit(
                                message,
                                a->polkit_action_ignore_inhibit,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                &challenge,
                                error);
                if (r < 0)
                        return r;

                if (r == 0) {
                        if (challenge) {
                                if (streq(result, "yes"))
                                        result = "inhibited";
                                /* If result is already "challenge" or "no", the held inhibitor has no effect */
                        } else {
                                if (streq(result, "yes"))
                                        result = "inhibitor-blocked";
                                else if (streq(result, "challenge"))
                                        result = "challenge-inhibitor-blocked";
                                /* If the result is already "no", the held inhibitor has no effect */
                        }
                }
        }

        return sd_bus_reply_method_return(message, "s", result);
}

static int method_can_poweroff(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_POWEROFF, error);
}

static int method_can_reboot(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_REBOOT, error);
}

static int method_can_halt(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_HALT, error);
}

static int method_can_suspend(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_SUSPEND, error);
}

static int method_can_hibernate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_HIBERNATE, error);
}

static int method_can_hybrid_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_HYBRID_SLEEP, error);
}

static int method_can_suspend_then_hibernate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_SUSPEND_THEN_HIBERNATE, error);
}

static int method_can_sleep(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;

        return method_can_shutdown_or_sleep(m, message, HANDLE_SLEEP, error);
}

static int property_get_reboot_parameter(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        _cleanup_free_ char *parameter = NULL;
        int r;

        assert(bus);
        assert(reply);
        assert(userdata);

        r = read_reboot_parameter(&parameter);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "s", parameter);
}

static int method_set_reboot_parameter(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        const char *arg;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &arg);
        if (r < 0)
                return r;

        if (!reboot_parameter_is_valid(arg))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid reboot parameter '%s'.", arg);

        r = detect_container();
        if (r < 0)
                return r;
        if (r > 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED,
                                        "Reboot parameter not supported in containers, refusing.");

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.set-reboot-parameter",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = update_reboot_parameter_and_warn(arg, false);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_can_reboot_parameter(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _unused_ Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = detect_container();
        if (r < 0)
                return r;
        if (r > 0) /* Inside containers, specifying a reboot parameter, doesn't make much sense */
                return sd_bus_reply_method_return(message, "s", "na");

        return return_test_polkit(
                        message,
                        "org.freedesktop.login1.set-reboot-parameter",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        error);
}

static int property_get_reboot_to_firmware_setup(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {
        int r;

        assert(bus);
        assert(reply);
        assert(userdata);

        r = getenv_bool("SYSTEMD_REBOOT_TO_FIRMWARE_SETUP");
        if (r == -ENXIO) {
                /* EFI case: let's see what is currently configured in the EFI variables */
                r = efi_get_reboot_to_firmware();
                if (r < 0 && r != -EOPNOTSUPP)
                        log_warning_errno(r, "Failed to determine reboot-to-firmware-setup state: %m");
        } else if (r < 0)
                log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_FIRMWARE_SETUP: %m");
        else if (r > 0) {
                /* Non-EFI case: let's see whether /run/systemd/reboot-to-firmware-setup exists. */
                if (access("/run/systemd/reboot-to-firmware-setup", F_OK) < 0) {
                        if (errno != ENOENT)
                                log_warning_errno(errno, "Failed to check whether /run/systemd/reboot-to-firmware-setup exists: %m");

                        r = false;
                } else
                        r = true;
        }

        return sd_bus_message_append(reply, "b", r > 0);
}

static int method_set_reboot_to_firmware_setup(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        bool use_efi;
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0)
                return r;

        r = getenv_bool("SYSTEMD_REBOOT_TO_FIRMWARE_SETUP");
        if (r == -ENXIO) {
                /* EFI case: let's see what the firmware supports */

                r = efi_reboot_to_firmware_supported();
                if (r == -EOPNOTSUPP)
                        return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Firmware does not support boot into firmware.");
                if (r < 0)
                        return r;

                use_efi = true;

        } else if (r <= 0) {
                /* non-EFI case: $SYSTEMD_REBOOT_TO_FIRMWARE_SETUP is set to off */

                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_FIRMWARE_SETUP: %m");

                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Firmware does not support boot into firmware.");
        } else
                /* non-EFI case: $SYSTEMD_REBOOT_TO_FIRMWARE_SETUP is set to on */
                use_efi = false;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.set-reboot-to-firmware-setup",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (use_efi) {
                r = efi_set_reboot_to_firmware(b);
                if (r < 0)
                        return r;
        } else {
                if (b) {
                        r = touch("/run/systemd/reboot-to-firmware-setup");
                        if (r < 0)
                                return r;
                } else {
                        if (unlink("/run/systemd/reboot-to-firmware-setup") < 0 && errno != ENOENT)
                                return -errno;
                }
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_can_reboot_to_firmware_setup(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _unused_ Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = getenv_bool("SYSTEMD_REBOOT_TO_FIRMWARE_SETUP");
        if (r == -ENXIO) {
                /* EFI case: let's see what the firmware supports */

                r = efi_reboot_to_firmware_supported();
                if (r < 0) {
                        if (r != -EOPNOTSUPP)
                                log_warning_errno(r, "Failed to determine whether reboot to firmware is supported: %m");

                        return sd_bus_reply_method_return(message, "s", "na");
                }

        } else if (r <= 0) {
                /* Non-EFI case: let's trust $SYSTEMD_REBOOT_TO_FIRMWARE_SETUP */

                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_FIRMWARE_SETUP: %m");

                return sd_bus_reply_method_return(message, "s", "na");
        }

        return return_test_polkit(
                        message,
                        "org.freedesktop.login1.set-reboot-to-firmware-setup",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        error);
}

static int property_get_reboot_to_boot_loader_menu(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        uint64_t x = UINT64_MAX;
        int r;

        assert(bus);
        assert(reply);
        assert(userdata);

        r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU");
        if (r == -ENXIO) {
                /* EFI case: returns the current value of LoaderConfigTimeoutOneShot. Three cases are distinguished:
                 *
                 *     1. Variable not set, boot into boot loader menu is not enabled (we return UINT64_MAX to the user)
                 *     2. Variable set to "0", boot into boot loader menu is enabled with no timeout (we return 0 to the user)
                 *     3. Variable set to numeric value formatted in ASCII, boot into boot loader menu with the specified timeout in seconds
                 */

                r = efi_loader_get_config_timeout_one_shot(&x);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to read LoaderConfigTimeoutOneShot variable, ignoring: %m");
                }

        } else if (r < 0)
                log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU: %m");
        else if (r > 0) {
                _cleanup_free_ char *v = NULL;

                /* Non-EFI case, let's process /run/systemd/reboot-to-boot-loader-menu. */

                r = read_one_line_file("/run/systemd/reboot-to-boot-loader-menu", &v);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to read /run/systemd/reboot-to-boot-loader-menu: %m");
                } else {
                        r = safe_atou64(v, &x);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse /run/systemd/reboot-to-boot-loader-menu: %m");
                }
        }

        return sd_bus_message_append(reply, "t", x);
}

static int method_set_reboot_to_boot_loader_menu(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        bool use_efi;
        uint64_t x;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &x);
        if (r < 0)
                return r;

        r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU");
        if (r == -ENXIO) {
                uint64_t features;

                /* EFI case: let's see if booting into boot loader menu is supported. */

                r = efi_loader_get_features(&features);
                if (r < 0)
                        log_warning_errno(r, "Failed to determine whether reboot to boot loader menu is supported: %m");
                if (r < 0 || !FLAGS_SET(features, EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT))
                        return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Boot loader does not support boot into boot loader menu.");

                use_efi = true;

        } else if (r <= 0) {
                /* non-EFI case: $SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU is set to off */

                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU: %m");

                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Boot loader does not support boot into boot loader menu.");
        } else
                /* non-EFI case: $SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU is set to on */
                use_efi = false;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.set-reboot-to-boot-loader-menu",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (use_efi) {
                if (x == UINT64_MAX)
                        r = efi_set_variable(EFI_LOADER_VARIABLE_STR("LoaderConfigTimeoutOneShot"), NULL, 0);
                else {
                        char buf[DECIMAL_STR_MAX(uint64_t) + 1];
                        xsprintf(buf, "%" PRIu64, DIV_ROUND_UP(x, USEC_PER_SEC)); /* second granularity */

                        r = efi_set_variable_string(EFI_LOADER_VARIABLE_STR("LoaderConfigTimeoutOneShot"), buf);
                }
                if (r < 0)
                        return r;
        } else {
                if (x == UINT64_MAX) {
                        if (unlink("/run/systemd/reboot-to-boot-loader-menu") < 0 && errno != ENOENT)
                                return -errno;
                } else {
                        r = write_string_filef("/run/systemd/reboot-to-boot-loader-menu",
                                               WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL,
                                               "%" PRIu64, x); /* μs granularity */
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_can_reboot_to_boot_loader_menu(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _unused_ Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU");
        if (r == -ENXIO) {
                uint64_t features = 0;

                /* EFI case, let's see if booting into boot loader menu is supported. */

                r = efi_loader_get_features(&features);
                if (r < 0)
                        log_warning_errno(r, "Failed to determine whether reboot to boot loader menu is supported: %m");
                if (r < 0 || !FLAGS_SET(features, EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT))
                        return sd_bus_reply_method_return(message, "s", "na");

        } else if (r <= 0) {
                /* Non-EFI case: let's trust $SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU */

                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU: %m");

                return sd_bus_reply_method_return(message, "s", "na");
        }

        return return_test_polkit(
                        message,
                        "org.freedesktop.login1.set-reboot-to-boot-loader-menu",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        error);
}

static int property_get_reboot_to_boot_loader_entry(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *v = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *x = NULL;
        int r;

        assert(bus);
        assert(reply);

        r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY");
        if (r == -ENXIO) {
                /* EFI case: let's read the LoaderEntryOneShot variable */

                r = efi_loader_update_entry_one_shot_cache(&m->efi_loader_entry_one_shot, &m->efi_loader_entry_one_shot_stat);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to read LoaderEntryOneShot variable, ignoring: %m");
                } else
                        x = m->efi_loader_entry_one_shot;

        } else if (r < 0)
                log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY: %m");
        else if (r > 0) {

                /* Non-EFI case, let's process /run/systemd/reboot-to-boot-loader-entry. */

                r = read_one_line_file("/run/systemd/reboot-to-boot-loader-entry", &v);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to read /run/systemd/reboot-to-boot-loader-entry, ignoring: %m");
                } else if (!efi_loader_entry_name_valid(v))
                        log_warning("/run/systemd/reboot-to-boot-loader-entry is not valid, ignoring.");
                else
                        x = v;
        }

        return sd_bus_message_append(reply, "s", x);
}

static int boot_loader_entry_exists(Manager *m, const char *id) {
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        int r;

        assert(m);
        assert(id);

        r = boot_config_load_auto(&config, NULL, NULL);
        if (r < 0 && r != -ENOKEY) /* don't complain if no GPT is found, hence skip ENOKEY */
                return r;

        r = manager_read_efi_boot_loader_entries(m);
        if (r >= 0)
                (void) boot_config_augment_from_loader(&config, m->efi_boot_loader_entries, /* auto_only= */ true);

        return !!boot_config_find_entry(&config, id);
}

static int method_set_reboot_to_boot_loader_entry(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        bool use_efi;
        const char *v;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &v);
        if (r < 0)
                return r;

        if (isempty(v))
                v = NULL;
        else if (efi_loader_entry_name_valid(v)) {
                r = boot_loader_entry_exists(m, v);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Boot loader entry '%s' is not known.", v);
        } else
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Boot loader entry name '%s' is not valid, refusing.", v);

        r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY");
        if (r == -ENXIO) {
                uint64_t features;

                /* EFI case: let's see if booting into boot loader entry is supported. */

                r = efi_loader_get_features(&features);
                if (r < 0)
                        log_warning_errno(r, "Failed to determine whether reboot into boot loader entry is supported: %m");
                if (r < 0 || !FLAGS_SET(features, EFI_LOADER_FEATURE_ENTRY_ONESHOT))
                        return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Loader does not support boot into boot loader entry.");

                use_efi = true;

        } else if (r <= 0) {
                /* non-EFI case: $SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY is set to off */

                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY: %m");

                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Loader does not support boot into boot loader entry.");
        } else
                /* non-EFI case: $SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY is set to on */
                use_efi = false;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.set-reboot-to-boot-loader-entry",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (use_efi) {
                if (isempty(v))
                        /* Delete item */
                        r = efi_set_variable(EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"), NULL, 0);
                else
                        r = efi_set_variable_string(EFI_LOADER_VARIABLE_STR("LoaderEntryOneShot"), v);
                if (r < 0)
                        return r;
        } else {
                if (isempty(v)) {
                        if (unlink("/run/systemd/reboot-to-boot-loader-entry") < 0 && errno != ENOENT)
                                return -errno;
                } else {
                        r = write_string_file("/run/systemd/reboot-boot-to-loader-entry", v, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_reply_method_return(message, NULL);
}

static int method_can_reboot_to_boot_loader_entry(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _unused_ Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY");
        if (r == -ENXIO) {
                uint64_t features = 0;

                /* EFI case, let's see if booting into boot loader entry is supported. */

                r = efi_loader_get_features(&features);
                if (r < 0)
                        log_warning_errno(r, "Failed to determine whether reboot to boot loader entry is supported: %m");
                if (r < 0 || !FLAGS_SET(features, EFI_LOADER_FEATURE_ENTRY_ONESHOT))
                        return sd_bus_reply_method_return(message, "s", "na");

        } else if (r <= 0) {
                /* Non-EFI case: let's trust $SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY */

                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY: %m");

                return sd_bus_reply_method_return(message, "s", "na");
        }

        return return_test_polkit(
                        message,
                        "org.freedesktop.login1.set-reboot-to-boot-loader-entry",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        error);
}

static int property_get_boot_loader_entries(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        Manager *m = ASSERT_PTR(userdata);
        size_t i;
        int r;

        assert(bus);
        assert(reply);

        r = boot_config_load_auto(&config, NULL, NULL);
        if (r < 0 && r != -ENOKEY) /* don't complain if there's no GPT found */
                return r;

        r = manager_read_efi_boot_loader_entries(m);
        if (r >= 0)
                (void) boot_config_augment_from_loader(&config, m->efi_boot_loader_entries, /* auto_only= */ true);

        r = sd_bus_message_open_container(reply, 'a', "s");
        if (r < 0)
                return r;

        for (i = 0; i < config.n_entries; i++) {
                BootEntry *e = config.entries + i;

                r = sd_bus_message_append(reply, "s", e->id);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int method_set_wall_message(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        int r;
        Manager *m = ASSERT_PTR(userdata);
        char *wall_message;
        int enable_wall_messages;

        assert(message);

        r = sd_bus_message_read(message, "sb", &wall_message, &enable_wall_messages);
        if (r < 0)
                return r;

        if (strlen(wall_message) > WALL_MESSAGE_MAX)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                        "Wall message too long, maximum permitted length is %u characters.",
                        WALL_MESSAGE_MAX);

        /* Short-circuit the operation if the desired state is already in place, to
         * avoid an unnecessary polkit permission check. */
        if (streq_ptr(m->wall_message, empty_to_null(wall_message)) &&
            m->wall_messages == enable_wall_messages)
                goto done;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.login1.set-wall-message",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = free_and_strdup(&m->wall_message, empty_to_null(wall_message));
        if (r < 0)
                return log_oom();

        m->wall_messages = enable_wall_messages;

 done:
        return sd_bus_reply_method_return(message, NULL);
}

static int method_inhibit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        const char *who, *why, *what, *mode;
        _cleanup_free_ char *id = NULL;
        _cleanup_close_ int fifo_fd = -EBADF;
        Manager *m = ASSERT_PTR(userdata);
        InhibitMode mm;
        InhibitWhat w;
        uid_t uid;
        _unused_ bool error_or_denial = false;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "ssss", &what, &who, &why, &mode);
        if (r < 0)
                return r;

        w = inhibit_what_from_string(what);
        if (w <= 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid what specification %s", what);

        mm = inhibit_mode_from_string(mode);
        if (mm < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid mode specification %s", mode);

        /* Delay is only supported for shutdown/sleep */
        if (mm == INHIBIT_DELAY && (w & ~(INHIBIT_SHUTDOWN|INHIBIT_SLEEP)))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS,
                                        "Delay inhibitors only supported for shutdown and sleep");

        /* Don't allow taking delay locks while we are already
         * executing the operation. We shouldn't create the impression
         * that the lock was successful if the machine is about to go
         * down/suspend any moment. */
        if (m->delayed_action && m->delayed_action->inhibit_what & w)
                return sd_bus_error_set(error, BUS_ERROR_OPERATION_IN_PROGRESS,
                                        "The operation inhibition has been requested for is already running");

        BIT_FOREACH(i, w) {
                const InhibitWhat v = 1U << i;

                r = bus_verify_polkit_async(
                                message,
                                v == INHIBIT_SHUTDOWN             ? (IN_SET(mm, INHIBIT_BLOCK, INHIBIT_BLOCK_WEAK) ? "org.freedesktop.login1.inhibit-block-shutdown" : "org.freedesktop.login1.inhibit-delay-shutdown") :
                                v == INHIBIT_SLEEP                ? (IN_SET(mm, INHIBIT_BLOCK, INHIBIT_BLOCK_WEAK) ? "org.freedesktop.login1.inhibit-block-sleep"    : "org.freedesktop.login1.inhibit-delay-sleep") :
                                v == INHIBIT_IDLE                 ? "org.freedesktop.login1.inhibit-block-idle" :
                                v == INHIBIT_HANDLE_POWER_KEY     ? "org.freedesktop.login1.inhibit-handle-power-key" :
                                v == INHIBIT_HANDLE_SUSPEND_KEY   ? "org.freedesktop.login1.inhibit-handle-suspend-key" :
                                v == INHIBIT_HANDLE_REBOOT_KEY    ? "org.freedesktop.login1.inhibit-handle-reboot-key" :
                                v == INHIBIT_HANDLE_HIBERNATE_KEY ? "org.freedesktop.login1.inhibit-handle-hibernate-key" :
                                                                "org.freedesktop.login1.inhibit-handle-lid-switch",
                                /* details= */ NULL,
                                &m->polkit_registry,
                                error);
                if (r < 0) {
                        /* If we get -EBUSY, it means a polkit decision was made, but not for
                         * this action in particular. Assuming there are more actions requested,
                         * ignore that error and allow the decision to be revealed later. */
                        if ((~v & w) && r == -EBUSY)
                                error_or_denial = true;
                        else
                                return r;
                }
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        /* If error_or_denial was set above, it means that a polkit denial or
         * error was deferred for a future call to bus_verify_polkit_async()
         * to catch. In any case, it also means that the payload guarded by
         * these polkit calls should never be executed, and hence we should
         * never reach this point. */
        assert(!error_or_denial);

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        r = bus_creds_get_pidref(creds, &pidref);
        if (r < 0)
                return r;

        if (hashmap_size(m->inhibitors) >= m->inhibitors_max)
                return sd_bus_error_setf(error, SD_BUS_ERROR_LIMITS_EXCEEDED,
                                         "Maximum number of inhibitors (%" PRIu64 ") reached, refusing further inhibitors.",
                                         m->inhibitors_max);

        do {
                id = mfree(id);

                if (asprintf(&id, "%" PRIu64, ++m->inhibit_counter) < 0)
                        return -ENOMEM;

        } while (hashmap_get(m->inhibitors, id));

        _cleanup_(inhibitor_freep) Inhibitor *i = NULL;
        r = manager_add_inhibitor(m, id, &i);
        if (r < 0)
                return r;

        i->what = w;
        i->mode = mm;
        i->pid = TAKE_PIDREF(pidref);
        i->uid = uid;
        i->why = strdup(why);
        i->who = strdup(who);

        if (!i->why || !i->who)
                return -ENOMEM;

        fifo_fd = inhibitor_create_fifo(i);
        if (fifo_fd < 0)
                return fifo_fd;

        r = inhibitor_start(i);
        if (r < 0)
                return r;
        TAKE_PTR(i);

        return sd_bus_reply_method_return(message, "h", fifo_fd);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_WRITABLE_PROPERTY("EnableWallMessages", "b", bus_property_get_bool, bus_property_set_bool, offsetof(Manager, wall_messages), 0),
        SD_BUS_WRITABLE_PROPERTY("WallMessage", "s", NULL, NULL, offsetof(Manager, wall_message), 0),

        SD_BUS_PROPERTY("NAutoVTs", "u", NULL, offsetof(Manager, n_autovts), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillOnlyUsers", "as", NULL, offsetof(Manager, kill_only_users), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillExcludeUsers", "as", NULL, offsetof(Manager, kill_exclude_users), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("KillUserProcesses", "b", bus_property_get_bool, offsetof(Manager, kill_user_processes), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RebootParameter", "s", property_get_reboot_parameter, 0, 0),
        SD_BUS_PROPERTY("RebootToFirmwareSetup", "b", property_get_reboot_to_firmware_setup, 0, 0),
        SD_BUS_PROPERTY("RebootToBootLoaderMenu", "t", property_get_reboot_to_boot_loader_menu, 0, 0),
        SD_BUS_PROPERTY("RebootToBootLoaderEntry", "s", property_get_reboot_to_boot_loader_entry, 0, 0),
        SD_BUS_PROPERTY("BootLoaderEntries", "as", property_get_boot_loader_entries, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BlockInhibited", "s", property_get_inhibited, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("BlockWeakInhibited", "s", property_get_inhibited, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DelayInhibited", "s", property_get_inhibited, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("InhibitDelayMaxUSec", "t", NULL, offsetof(Manager, inhibit_delay_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UserStopDelayUSec", "t", NULL, offsetof(Manager, user_stop_delay), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SleepOperation", "as", property_get_sleep_operations, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandlePowerKey", "s", property_get_handle_action, offsetof(Manager, handle_power_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandlePowerKeyLongPress", "s", property_get_handle_action, offsetof(Manager, handle_power_key_long_press), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleRebootKey", "s", property_get_handle_action, offsetof(Manager, handle_reboot_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleRebootKeyLongPress", "s", property_get_handle_action, offsetof(Manager, handle_reboot_key_long_press), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleSuspendKey", "s", property_get_handle_action, offsetof(Manager, handle_suspend_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleSuspendKeyLongPress", "s", property_get_handle_action, offsetof(Manager, handle_suspend_key_long_press), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleHibernateKey", "s", property_get_handle_action, offsetof(Manager, handle_hibernate_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleHibernateKeyLongPress", "s", property_get_handle_action, offsetof(Manager, handle_hibernate_key_long_press), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleLidSwitch", "s", property_get_handle_action, offsetof(Manager, handle_lid_switch), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleLidSwitchExternalPower", "s", property_get_handle_action, offsetof(Manager, handle_lid_switch_ep), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleLidSwitchDocked", "s", property_get_handle_action, offsetof(Manager, handle_lid_switch_docked), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HandleSecureAttentionKey", "s", property_get_handle_action, offsetof(Manager, handle_secure_attention_key), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("HoldoffTimeoutUSec", "t", NULL, offsetof(Manager, holdoff_timeout_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleAction", "s", property_get_handle_action, offsetof(Manager, idle_action), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IdleActionUSec", "t", NULL, offsetof(Manager, idle_action_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PreparingForShutdown", "b", property_get_preparing, 0, 0),
        SD_BUS_PROPERTY("PreparingForShutdownWithMetadata", "a{sv}", property_get_preparing_shutdown_with_metadata, 0, 0),
        SD_BUS_PROPERTY("PreparingForSleep", "b", property_get_preparing, 0, 0),
        SD_BUS_PROPERTY("ScheduledShutdown", "(st)", property_get_scheduled_shutdown, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("DesignatedMaintenanceTime", "s", property_get_maintenance_time, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Docked", "b", property_get_docked, 0, 0),
        SD_BUS_PROPERTY("LidClosed", "b", property_get_lid_closed, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("OnExternalPower", "b", property_get_on_external_power, 0, 0),
        SD_BUS_PROPERTY("RemoveIPC", "b", bus_property_get_bool, offsetof(Manager, remove_ipc), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeDirectorySize", "t", NULL, offsetof(Manager, runtime_dir_size), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeDirectoryInodesMax", "t", NULL, offsetof(Manager, runtime_dir_inodes), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("InhibitorsMax", "t", NULL, offsetof(Manager, inhibitors_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NCurrentInhibitors", "t", property_get_hashmap_size, offsetof(Manager, inhibitors), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("SessionsMax", "t", NULL, offsetof(Manager, sessions_max), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NCurrentSessions", "t", property_get_hashmap_size, offsetof(Manager, sessions), 0),
        SD_BUS_PROPERTY("UserTasksMax", "t", property_get_compat_user_tasks_max, 0, SD_BUS_VTABLE_PROPERTY_CONST|SD_BUS_VTABLE_HIDDEN),
        SD_BUS_PROPERTY("StopIdleSessionUSec", "t", NULL, offsetof(Manager, stop_idle_session_usec), SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD_WITH_ARGS("GetSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_RESULT("o", object_path),
                                method_get_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetSessionByPID",
                                SD_BUS_ARGS("u", pid),
                                SD_BUS_RESULT("o", object_path),
                                method_get_session_by_pid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUser",
                                SD_BUS_ARGS("u", uid),
                                SD_BUS_RESULT("o", object_path),
                                method_get_user,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUserByPID",
                                SD_BUS_ARGS("u", pid),
                                SD_BUS_RESULT("o", object_path),
                                method_get_user_by_pid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetSeat",
                                SD_BUS_ARGS("s", seat_id),
                                SD_BUS_RESULT("o", object_path),
                                method_get_seat,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListSessions",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(susso)", sessions),
                                method_list_sessions,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListSessionsEx",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(sussussbto)", sessions),
                                method_list_sessions_ex,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListUsers",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(uso)", users),
                                method_list_users,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListSeats",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(so)", seats),
                                method_list_seats,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListInhibitors",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(ssssuu)", inhibitors),
                                method_list_inhibitors,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CreateSession",
                                SD_BUS_ARGS("u", uid,
                                            "u", pid,
                                            "s", service,
                                            "s", type,
                                            "s", class,
                                            "s", desktop,
                                            "s", seat_id,
                                            "u", vtnr,
                                            "s", tty,
                                            "s", display,
                                            "b", remote,
                                            "s", remote_user,
                                            "s", remote_host,
                                            "a(sv)", properties),
                                SD_BUS_RESULT("s", session_id,
                                              "o", object_path,
                                              "s", runtime_path,
                                              "h", fifo_fd,
                                              "u", uid,
                                              "s", seat_id,
                                              "u", vtnr,
                                              "b", existing),
                                method_create_session,
                                0),
        SD_BUS_METHOD_WITH_ARGS("CreateSessionWithPIDFD",
                                SD_BUS_ARGS("u", uid,
                                            "h", pidfd,
                                            "s", service,
                                            "s", type,
                                            "s", class,
                                            "s", desktop,
                                            "s", seat_id,
                                            "u", vtnr,
                                            "s", tty,
                                            "s", display,
                                            "b", remote,
                                            "s", remote_user,
                                            "s", remote_host,
                                            "t", flags,
                                            "a(sv)", properties),
                                SD_BUS_RESULT("s", session_id,
                                              "o", object_path,
                                              "s", runtime_path,
                                              "h", fifo_fd,
                                              "u", uid,
                                              "s", seat_id,
                                              "u", vtnr,
                                              "b", existing),
                                method_create_session_pidfd,
                                0),
        SD_BUS_METHOD_WITH_ARGS("ReleaseSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_NO_RESULT,
                                method_release_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ActivateSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_NO_RESULT,
                                method_activate_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ActivateSessionOnSeat",
                                SD_BUS_ARGS("s", session_id, "s", seat_id),
                                SD_BUS_NO_RESULT,
                                method_activate_session_on_seat,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("LockSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_NO_RESULT,
                                method_lock_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("UnlockSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_NO_RESULT,
                                method_lock_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("LockSessions",
                      NULL,
                      NULL,
                      method_lock_sessions,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("UnlockSessions",
                      NULL,
                      NULL,
                      method_lock_sessions,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("KillSession",
                                SD_BUS_ARGS("s", session_id, "s", whom, "i", signal_number),
                                SD_BUS_NO_RESULT,
                                method_kill_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("KillUser",
                                SD_BUS_ARGS("u", uid, "i", signal_number),
                                SD_BUS_NO_RESULT,
                                method_kill_user,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TerminateSession",
                                SD_BUS_ARGS("s", session_id),
                                SD_BUS_NO_RESULT,
                                method_terminate_session,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TerminateUser",
                                SD_BUS_ARGS("u", uid),
                                SD_BUS_NO_RESULT,
                                method_terminate_user,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TerminateSeat",
                                SD_BUS_ARGS("s", seat_id),
                                SD_BUS_NO_RESULT,
                                method_terminate_seat,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetUserLinger",
                                SD_BUS_ARGS("u", uid, "b", enable, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_user_linger,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AttachDevice",
                                SD_BUS_ARGS("s", seat_id, "s", sysfs_path, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_attach_device,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("FlushDevices",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_flush_devices,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("PowerOff",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_poweroff,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("PowerOffWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_poweroff,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Reboot",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_reboot,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RebootWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_reboot,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Halt",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_halt,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("HaltWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_halt,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Suspend",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_suspend,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SuspendWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_suspend,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Hibernate",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_hibernate,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("HibernateWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_hibernate,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("HybridSleep",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_hybrid_sleep,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("HybridSleepWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_hybrid_sleep,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SuspendThenHibernate",
                                SD_BUS_ARGS("b", interactive),
                                SD_BUS_NO_RESULT,
                                method_suspend_then_hibernate,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SuspendThenHibernateWithFlags",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_suspend_then_hibernate,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Sleep",
                                SD_BUS_ARGS("t", flags),
                                SD_BUS_NO_RESULT,
                                method_sleep,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanPowerOff",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_poweroff,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanReboot",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_reboot,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanHalt",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_halt,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanSuspend",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_suspend,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanHibernate",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_hibernate,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanHybridSleep",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_hybrid_sleep,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanSuspendThenHibernate",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_suspend_then_hibernate,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanSleep",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_sleep,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ScheduleShutdown",
                                SD_BUS_ARGS("s", type, "t", usec),
                                SD_BUS_NO_RESULT,
                                method_schedule_shutdown,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CancelScheduledShutdown",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("b", cancelled),
                                method_cancel_scheduled_shutdown,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Inhibit",
                                SD_BUS_ARGS("s", what, "s", who, "s", why, "s", mode),
                                SD_BUS_RESULT("h", pipe_fd),
                                method_inhibit,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanRebootParameter",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_reboot_parameter,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetRebootParameter",
                                SD_BUS_ARGS("s", parameter),
                                SD_BUS_NO_RESULT,
                                method_set_reboot_parameter,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanRebootToFirmwareSetup",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_reboot_to_firmware_setup,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetRebootToFirmwareSetup",
                                SD_BUS_ARGS("b", enable),
                                SD_BUS_NO_RESULT,
                                method_set_reboot_to_firmware_setup,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanRebootToBootLoaderMenu",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_reboot_to_boot_loader_menu,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetRebootToBootLoaderMenu",
                                SD_BUS_ARGS("t", timeout),
                                SD_BUS_NO_RESULT,
                                method_set_reboot_to_boot_loader_menu,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CanRebootToBootLoaderEntry",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("s", result),
                                method_can_reboot_to_boot_loader_entry,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetRebootToBootLoaderEntry",
                                SD_BUS_ARGS("s", boot_loader_entry),
                                SD_BUS_NO_RESULT,
                                method_set_reboot_to_boot_loader_entry,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetWallMessage",
                                SD_BUS_ARGS("s", wall_message, "b", enable),
                                SD_BUS_NO_RESULT,
                                method_set_wall_message,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_ARGS("SecureAttentionKey",
                                SD_BUS_ARGS("s", seat_id, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("SessionNew",
                                SD_BUS_ARGS("s", session_id, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("SessionRemoved",
                                SD_BUS_ARGS("s", session_id, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("UserNew",
                                SD_BUS_ARGS("u", uid, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("UserRemoved",
                                SD_BUS_ARGS("u", uid, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("SeatNew",
                                SD_BUS_ARGS("s", seat_id, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("SeatRemoved",
                                SD_BUS_ARGS("s", seat_id, "o", object_path),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("PrepareForShutdown",
                                SD_BUS_ARGS("b", start),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("PrepareForShutdownWithMetadata",
                                SD_BUS_ARGS("b", start, "a{sv}", metadata),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("PrepareForSleep",
                                SD_BUS_ARGS("b", start),
                                0),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS(&seat_object,
                                        &session_object,
                                        &user_object),
};

static void session_jobs_reply(Session *s, uint32_t jid, const char *unit, const char *result) {
        assert(s);
        assert(unit);

        if (!s->started)
                return;

        if (result && !streq(result, "done")) {
                _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;

                sd_bus_error_setf(&e, BUS_ERROR_JOB_FAILED,
                                  "Job %u for unit '%s' failed with '%s'", jid, unit, result);

                (void) session_send_create_reply(s, &e);
                (void) session_send_upgrade_reply(s, &e);
                return;
        }

        (void) session_send_create_reply(s, /* error= */ NULL);
        (void) session_send_upgrade_reply(s, /* error= */ NULL);
}

int match_job_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        const char *path, *result, *unit;
        uint32_t id;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "uoss", &id, &path, &unit, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (m->action_job && streq(m->action_job, path)) {
                assert(m->delayed_action);
                log_info("Operation '%s' finished.", handle_action_to_string(m->delayed_action->handle));

                /* Tell people that they now may take a lock again */
                (void) send_prepare_for(m, m->delayed_action, false);

                m->action_job = mfree(m->action_job);
                m->delayed_action = NULL;
                return 0;
        }

        Session *session;
        User *user;

        session = hashmap_get(m->session_units, unit);
        if (session) {
                if (streq_ptr(path, session->scope_job)) {
                        session->scope_job = mfree(session->scope_job);
                        session_jobs_reply(session, id, unit, result);

                        session_save(session);
                        user_save(session->user);
                }

                session_add_to_gc_queue(session);
        }

        user = hashmap_get(m->user_units, unit);
        if (user) {
                /* If the user is stopping, we're tracking stop jobs here. So don't send reply. */
                if (!user->stopping) {
                        char **user_job;
                        FOREACH_ARGUMENT(user_job, &user->runtime_dir_job, &user->service_manager_job)
                                if (streq_ptr(path, *user_job)) {
                                        *user_job = mfree(*user_job);

                                        LIST_FOREACH(sessions_by_user, s, user->sessions)
                                                /* Don't propagate user service failures to the client */
                                                session_jobs_reply(s, id, unit, /* result= */ NULL);

                                        user_save(user);
                                        break;
                                }
                }

                user_add_to_gc_queue(user);
        }

        return 0;
}

int match_unit_removed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        const char *path, *unit;
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        User *user;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "so", &unit, &path);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        session = hashmap_get(m->session_units, unit);
        if (session)
                session_add_to_gc_queue(session);

        user = hashmap_get(m->user_units, unit);
        if (user)
                user_add_to_gc_queue(user);

        return 0;
}

int match_properties_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_free_ char *unit = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *path;
        Session *session;
        User *user;
        int r;

        assert(message);

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        r = unit_name_from_dbus_path(path, &unit);
        if (r == -EINVAL) /* not a unit */
                return 0;
        if (r < 0) {
                log_oom();
                return 0;
        }

        session = hashmap_get(m->session_units, unit);
        if (session)
                session_add_to_gc_queue(session);

        user = hashmap_get(m->user_units, unit);
        if (user)
                user_add_to_gc_queue(user);

        return 0;
}

int match_reloading(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (b)
                return 0;

        /* systemd finished reloading, let's recheck all our sessions */
        log_debug("System manager has been reloaded, rechecking sessions...");

        HASHMAP_FOREACH(session, m->sessions)
                session_add_to_gc_queue(session);

        return 0;
}

int manager_send_changed_strv(Manager *manager, char **properties) {
        assert(manager);

        return sd_bus_emit_properties_changed_strv(
                        manager->bus,
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        properties);
}

int manager_start_scope(
                Manager *manager,
                const char *scope,
                const PidRef *pidref,
                bool allow_pidfd,
                const char *slice,
                const char *description,
                const char * const *requires,
                const char * const *wants,
                const char * const *extra_after,
                const char *requires_mounts_for,
                sd_bus_message *more_properties,
                sd_bus_error *error,
                char **ret_job) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        int r;

        assert(manager);
        assert(scope);
        assert(pidref_is_set(pidref));
        assert(ret_job);

        r = bus_message_new_method_call(manager->bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "ss", scope, "fail");
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return r;

        if (!isempty(slice)) {
                r = sd_bus_message_append(m, "(sv)", "Slice", "s", slice);
                if (r < 0)
                        return r;
        }

        if (!isempty(description)) {
                r = sd_bus_message_append(m, "(sv)", "Description", "s", description);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, requires) {
                r = sd_bus_message_append(m, "(sv)", "Requires", "as", 1, *i);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "(sv)", "After", "as", 1, *i);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, wants) {
                r = sd_bus_message_append(m, "(sv)", "Wants", "as", 1, *i);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "(sv)", "After", "as", 1, *i);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, extra_after) {
                r = sd_bus_message_append(m, "(sv)", "After", "as", 1, *i);
                if (r < 0)
                        return r;
        }

        if (!empty_or_root(requires_mounts_for)) {
                r = sd_bus_message_append(m, "(sv)", "RequiresMountsFor", "as", 1, requires_mounts_for);
                if (r < 0)
                        return r;
        }

        /* Make sure that the session shells are terminated with SIGHUP since bash and friends tend to ignore
         * SIGTERM */
        r = sd_bus_message_append(m, "(sv)", "SendSIGHUP", "b", true);
        if (r < 0)
                return r;

        r = bus_append_scope_pidref(m, pidref, allow_pidfd);
        if (r < 0)
                return r;

        /* For login session scopes, if a process is OOM killed by the kernel, *don't* terminate the rest of
           the scope */
        r = sd_bus_message_append(m, "(sv)", "OOMPolicy", "s", "continue");
        if (r < 0)
                return r;

        /* disable TasksMax= for the session scope, rely on the slice setting for it */
        r = sd_bus_message_append(m, "(sv)", "TasksMax", "t", UINT64_MAX);
        if (r < 0)
                return bus_log_create_error(r);

        if (more_properties) {
                /* If TasksMax also appears here, it will overwrite the default value set above */
                r = sd_bus_message_copy(m, more_properties, true);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return r;

        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return r;

        r = sd_bus_call(manager->bus, m, 0, &e, &reply);
        if (r < 0) {
                /* If this failed with a property we couldn't write, this is quite likely because the server
                 * doesn't support PIDFDs yet, let's try without. */
                if (allow_pidfd &&
                    sd_bus_error_has_names(&e, SD_BUS_ERROR_UNKNOWN_PROPERTY, SD_BUS_ERROR_PROPERTY_READ_ONLY))
                        return manager_start_scope(
                                        manager,
                                        scope,
                                        pidref,
                                        /* allow_pidfd= */ false,
                                        slice,
                                        description,
                                        requires,
                                        wants,
                                        extra_after,
                                        requires_mounts_for,
                                        more_properties,
                                        error,
                                        ret_job);

                return sd_bus_error_move(error, &e);
        }

        return strdup_job(reply, ret_job);
}

int manager_start_unit(Manager *manager, const char *unit, sd_bus_error *error, char **ret_job) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(unit);
        assert(ret_job);

        r = bus_call_method(
                        manager->bus,
                        bus_systemd_mgr,
                        "StartUnit",
                        error,
                        &reply,
                        "ss", unit, "replace");
        if (r < 0)
                return r;

        return strdup_job(reply, ret_job);
}

int manager_stop_unit(
                Manager *manager,
                const char *unit,
                const char *job_mode,
                sd_bus_error *ret_error,
                char **ret_job) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(manager);
        assert(unit);
        assert(ret_job);

        r = bus_call_method(
                        manager->bus,
                        bus_systemd_mgr,
                        "StopUnit",
                        &error,
                        &reply,
                        "ss", unit, job_mode ?: "fail");
        if (r < 0) {
                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_SUCH_UNIT, BUS_ERROR_LOAD_FAILED)) {
                        *ret_job = NULL;
                        return 0;
                }

                sd_bus_error_move(ret_error, &error);
                return r;
        }

        r = strdup_job(reply, ret_job);
        if (r < 0)
                return r;

        return 1;
}

int manager_abandon_scope(Manager *manager, const char *scope, sd_bus_error *ret_error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(manager);
        assert(scope);

        path = unit_dbus_path_from_name(scope);
        if (!path)
                return -ENOMEM;

        r = sd_bus_call_method(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Scope",
                        "Abandon",
                        &error,
                        NULL,
                        NULL);
        if (r < 0) {
                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_SUCH_UNIT,
                                                   BUS_ERROR_LOAD_FAILED,
                                                   BUS_ERROR_SCOPE_NOT_RUNNING))
                        return 0;

                sd_bus_error_move(ret_error, &error);
                return r;
        }

        return 1;
}

int manager_kill_unit(Manager *manager, const char *unit, KillWhom whom, int signo, sd_bus_error *error) {
        assert(manager);
        assert(unit);
        assert(SIGNAL_VALID(signo));

        return bus_call_method(
                        manager->bus,
                        bus_systemd_mgr,
                        "KillUnit",
                        error,
                        NULL,
                        "ssi",
                        unit,
                        whom == KILL_LEADER ? "main" : "all",
                        signo);
}

int manager_unit_is_active(Manager *manager, const char *unit, sd_bus_error *ret_error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *path = NULL;
        const char *state;
        int r;

        assert(manager);
        assert(unit);

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveState",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                /* systemd might have dropped off momentarily, let's
                 * not make this an error */
                if (bus_error_is_connection(&error))
                        return true;

                /* If the unit is already unloaded then it's not
                 * active */
                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_SUCH_UNIT,
                                                   BUS_ERROR_LOAD_FAILED))
                        return false;

                sd_bus_error_move(ret_error, &error);
                return r;
        }

        r = sd_bus_message_read(reply, "s", &state);
        if (r < 0)
                return r;

        return !STR_IN_SET(state, "inactive", "failed");
}

int manager_job_is_active(Manager *manager, const char *path, sd_bus_error *ret_error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(manager);
        assert(path);

        r = sd_bus_get_property(
                        manager->bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Job",
                        "State",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                if (bus_error_is_connection(&error))
                        return true;

                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                        return false;

                sd_bus_error_move(ret_error, &error);
                return r;
        }

        /* We don't actually care about the state really. The fact
         * that we could read the job state is enough for us */

        return true;
}
