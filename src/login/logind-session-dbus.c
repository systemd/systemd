/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/eventfd.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-label.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "device-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "log.h"
#include "logind.h"
#include "logind-brightness.h"
#include "logind-dbus.h"
#include "logind-polkit.h"
#include "logind-seat.h"
#include "logind-seat-dbus.h"
#include "logind-session.h"
#include "logind-session-dbus.h"
#include "logind-session-device.h"
#include "logind-user.h"
#include "logind-user-dbus.h"
#include "path-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-record.h"
#include "user-util.h"

static int property_get_user(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        p = user_bus_path(s->user);
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(uo)", (uint32_t) s->user->user_record->uid, p);
}

static int property_get_name(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", s->user->user_record->user_name);
}

static int property_get_seat(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *p = NULL;
        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        p = s->seat ? seat_bus_path(s->seat) : strdup("/");
        if (!p)
                return -ENOMEM;

        return sd_bus_message_append(reply, "(so)", s->seat ? s->seat->id : "", p);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_type, session_type, SessionType);
static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_class, session_class, SessionClass);
static BUS_DEFINE_PROPERTY_GET(property_get_active, "b", Session, session_is_active);
static BUS_DEFINE_PROPERTY_GET2(property_get_state, "s", Session, session_get_state, session_state_to_string);

static int property_get_idle_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", session_get_idle_hint(s, NULL) > 0);
}

static int property_get_can_idle(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", SESSION_CLASS_CAN_IDLE(s->class));
}

static int property_get_can_lock(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", SESSION_CLASS_CAN_LOCK(s->class));
}

static int property_get_idle_since_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Session *s = ASSERT_PTR(userdata);
        dual_timestamp t = DUAL_TIMESTAMP_NULL;
        uint64_t u;
        int r;

        assert(bus);
        assert(reply);

        r = session_get_idle_hint(s, &t);
        if (r < 0)
                return r;

        u = streq(property, "IdleSinceHint") ? t.realtime : t.monotonic;

        return sd_bus_message_append(reply, "t", u);
}

static int property_get_locked_hint(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Session *s = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "b", session_get_locked_hint(s) > 0);
}

int bus_session_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        s->user->user_record->uid,
                        /* flags= */ 0,
                        &s->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_stop(s, /* force = */ true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_session_method_activate(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = check_polkit_chvt(message, s->manager, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_activate(s);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_session_method_lock(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.lock-sessions",
                        /* details= */ NULL,
                        s->user->user_record->uid,
                        /* flags= */ 0,
                        &s->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_send_lock(s, /* lock= */ strstr(sd_bus_message_get_member(message), "Lock"));
        if (r == -ENOTTY)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Session does not support lock screen.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_idle_hint(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Session *s = ASSERT_PTR(userdata);
        uid_t uid;
        int r, b;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0)
                return r;

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != s->user->user_record->uid)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Only owner of session may set idle hint");

        r = session_set_idle_hint(s, b);
        if (r == -ENOTTY)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Idle hint control is not supported on non-graphical and non-user sessions.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_locked_hint(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Session *s = ASSERT_PTR(userdata);
        uid_t uid;
        int r, b;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0)
                return r;

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != s->user->user_record->uid)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Only owner of session may set locked hint");

        r = session_set_locked_hint(s, b);
        if (r == -ENOTTY)
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Session does not support lock screen.");
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

int bus_session_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        const char *swhom;
        int32_t signo;
        KillWhom whom;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "si", &swhom, &signo);
        if (r < 0)
                return r;

        if (isempty(swhom))
                whom = KILL_ALL;
        else {
                whom = kill_whom_from_string(swhom);
                if (whom < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid kill parameter '%s'", swhom);
        }

        if (!SIGNAL_VALID(signo))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid signal %i", signo);

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        s->user->user_record->uid,
                        /* flags= */ 0,
                        &s->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = session_kill(s, whom, signo, error);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_take_control(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Session *s = ASSERT_PTR(userdata);
        int r, force;
        uid_t uid;

        assert(message);

        r = sd_bus_message_read(message, "b", &force);
        if (r < 0)
                return r;

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && (force || uid != s->user->user_record->uid))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Only owner of session may take control");

        r = session_set_controller(s, sd_bus_message_get_sender(message), force, true);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_release_control(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);

        assert(message);

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You are not in control of this session");

        session_drop_controller(s);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_type(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        const char *t;
        SessionType type;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &t);
        if (r < 0)
                return r;

        type = session_type_from_string(t);
        if (type < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid session type '%s'", t);

        if (!SESSION_CLASS_CAN_CHANGE_TYPE(s->class))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Session class doesn't support changing type.");

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You must be in control of this session to set type");

        session_set_type(s, type);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_class(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        Session *s = ASSERT_PTR(userdata);
        SessionClass class;
        const char *c;
        uid_t uid;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &c);
        if (r < 0)
                return r;

        class = session_class_from_string(c);
        if (class < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid session class '%s'", c);

        /* For now, we'll allow only upgrades user-incomplete → user */
        if (class != SESSION_USER)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Class may only be set to 'user'");

        if (s->class == SESSION_USER) /* No change, shortcut */
                return sd_bus_reply_method_return(message, NULL);
        if (s->class != SESSION_USER_INCOMPLETE)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Only sessions with class 'user-incomplete' may change class");

        if (s->upgrade_message)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                         "Set session class operation already in progress");

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != s->user->user_record->uid)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Only owner of session may change its class");

        session_set_class(s, class);

        s->upgrade_message = sd_bus_message_ref(message);

        r = session_send_upgrade_reply(s, /* error= */ NULL);
        if (r < 0)
                return r;

        return 1;
}

static int method_set_display(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        const char *display;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &display);
        if (r < 0)
                return r;

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You must be in control of this session to set display");

        if (!SESSION_TYPE_IS_GRAPHICAL(s->type))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Setting display is only supported for graphical sessions");

        r = session_set_display(s, display);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_tty(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        int fd, r, flags;
        _cleanup_free_ char *q = NULL;

        assert(message);

        r = sd_bus_message_read(message, "h", &fd);
        if (r < 0)
                return r;

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You must be in control of this session to set tty");

        assert(fd >= 0);

        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0)
                return -errno;
        if ((flags & O_ACCMODE_STRICT) != O_RDWR)
                return -EACCES;
        if (FLAGS_SET(flags, O_PATH))
                return -ENOTTY;

        r = getttyname_malloc(fd, &q);
        if (r < 0)
                return r;

        r = session_set_tty(s, q);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_take_device(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        uint32_t major, minor;
        _cleanup_(session_device_freep) SessionDevice *sd = NULL;
        dev_t dev;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "uu", &major, &minor);
        if (r < 0)
                return r;

        if (!DEVICE_MAJOR_VALID(major) || !DEVICE_MINOR_VALID(minor))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Device major/minor is not valid.");

        if (!SESSION_CLASS_CAN_TAKE_DEVICE(s->class))
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Session class doesn't support taking device control.");

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You are not in control of this session");

        dev = makedev(major, minor);
        sd = hashmap_get(s->devices, &dev);
        if (sd)
                /* We don't allow retrieving a device multiple times.
                 * The related ReleaseDevice call is not ref-counted.
                 * The caller should use dup() if it requires more
                 * than one fd (it would be functionally
                 * equivalent). */
                return sd_bus_error_set(error, BUS_ERROR_DEVICE_IS_TAKEN, "Device already taken");

        r = session_device_new(s, dev, true, &sd);
        if (r < 0)
                return r;

        r = session_device_save(sd);
        if (r < 0)
                return r;

        r = sd_bus_reply_method_return(message, "hb", sd->fd, !sd->active);
        if (r < 0)
                return r;

        session_save(s);
        TAKE_PTR(sd);

        return 1;
}

static int method_release_device(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        uint32_t major, minor;
        SessionDevice *sd;
        dev_t dev;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "uu", &major, &minor);
        if (r < 0)
                return r;

        if (!DEVICE_MAJOR_VALID(major) || !DEVICE_MINOR_VALID(minor))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Device major/minor is not valid.");

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You are not in control of this session");

        dev = makedev(major, minor);
        sd = hashmap_get(s->devices, &dev);
        if (!sd)
                return sd_bus_error_set(error, BUS_ERROR_DEVICE_NOT_TAKEN, "Device not taken");

        session_device_free(sd);
        session_save(s);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_pause_device_complete(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Session *s = ASSERT_PTR(userdata);
        uint32_t major, minor;
        SessionDevice *sd;
        dev_t dev;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "uu", &major, &minor);
        if (r < 0)
                return r;

        if (!DEVICE_MAJOR_VALID(major) || !DEVICE_MINOR_VALID(minor))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Device major/minor is not valid.");

        if (!session_is_controller(s, sd_bus_message_get_sender(message)))
                return sd_bus_error_set(error, BUS_ERROR_NOT_IN_CONTROL, "You are not in control of this session");

        dev = makedev(major, minor);
        sd = hashmap_get(s->devices, &dev);
        if (!sd)
                return sd_bus_error_set(error, BUS_ERROR_DEVICE_NOT_TAKEN, "Device not taken");

        session_device_complete_pause(sd);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_set_brightness(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        const char *subsystem, *name, *seat;
        Session *s = ASSERT_PTR(userdata);
        uint32_t brightness;
        uid_t uid;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "ssu", &subsystem, &name, &brightness);
        if (r < 0)
                return r;

        if (!STR_IN_SET(subsystem, "backlight", "leds"))
                return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Subsystem type %s not supported, must be one of 'backlight' or 'leds'.", subsystem);
        if (!filename_is_valid(name))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Not a valid device name %s, refusing.", name);

        if (!s->seat)
                return sd_bus_error_set(error, BUS_ERROR_NOT_YOUR_DEVICE, "Your session has no seat, refusing.");
        if (s->seat->active != s)
                return sd_bus_error_set(error, BUS_ERROR_NOT_YOUR_DEVICE, "Session is not in foreground, refusing.");

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != s->user->user_record->uid)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Only owner of session may change brightness.");

        r = sd_device_new_from_subsystem_sysname(&d, subsystem, name);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to open device %s:%s: %m", subsystem, name);

        r = device_get_seat(d, &seat);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to get seat of %s:%s: %m", subsystem, name);
        if (!streq(seat, s->seat->id))
                return sd_bus_error_setf(error, BUS_ERROR_NOT_YOUR_DEVICE, "Device %s:%s does not belong to your seat %s, refusing.", subsystem, name, s->seat->id);

        r = manager_write_brightness(s->manager, d, brightness, message);
        if (r < 0)
                return r;

        return 1;
}

static int session_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        _cleanup_free_ char *e = NULL;
        sd_bus_message *message;
        Manager *m = ASSERT_PTR(userdata);
        Session *session;
        const char *p;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        p = startswith(path, "/org/freedesktop/login1/session/");
        if (!p)
                return 0;

        e = bus_label_unescape(p);
        if (!e)
                return -ENOMEM;

        message = sd_bus_get_current_message(bus);

        r = manager_get_session_from_creds(m, message, e, error, &session);
        if (r == -ENXIO) {
                sd_bus_error_free(error);
                return 0;
        }
        if (r < 0)
                return r;

        *found = session;
        return 1;
}

char* session_bus_path(Session *s) {
        _cleanup_free_ char *t = NULL;

        assert(s);

        t = bus_label_escape(s->id);
        if (!t)
                return NULL;

        return strjoin("/org/freedesktop/login1/session/", t);
}

static int session_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        sd_bus_message *message;
        Manager *m = userdata;
        Session *session;
        int r;

        assert(bus);
        assert(path);
        assert(nodes);

        HASHMAP_FOREACH(session, m->sessions) {
                char *p;

                p = session_bus_path(session);
                if (!p)
                        return -ENOMEM;

                r = strv_consume(&l, p);
                if (r < 0)
                        return r;
        }

        message = sd_bus_get_current_message(bus);
        if (message) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_SESSION|SD_BUS_CREDS_OWNER_UID|SD_BUS_CREDS_AUGMENT, &creds);
                if (r >= 0) {
                        bool may_auto = false;
                        const char *name;

                        r = sd_bus_creds_get_session(creds, &name);
                        if (r >= 0) {
                                session = hashmap_get(m->sessions, name);
                                if (session) {
                                        r = strv_extend(&l, "/org/freedesktop/login1/session/self");
                                        if (r < 0)
                                                return r;

                                        may_auto = true;
                                }
                        }

                        if (!may_auto) {
                                uid_t uid;

                                r = sd_bus_creds_get_owner_uid(creds, &uid);
                                if (r >= 0) {
                                        User *user;

                                        user = hashmap_get(m->users, UID_TO_PTR(uid));
                                        may_auto = user && user->display;
                                }
                        }

                        if (may_auto) {
                                r = strv_extend(&l, "/org/freedesktop/login1/session/auto");
                                if (r < 0)
                                        return r;
                        }
                }
        }

        *nodes = TAKE_PTR(l);
        return 1;
}

int session_send_signal(Session *s, bool new_session) {
        _cleanup_free_ char *p = NULL;

        assert(s);

        p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_signal(
                        s->manager->bus,
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        new_session ? "SessionNew" : "SessionRemoved",
                        "so", s->id, p);
}

int session_send_changed_strv(Session *s, char **properties) {
        _cleanup_free_ char *p = NULL;

        assert(s);

        if (!s->started)
                return 0;

        p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_properties_changed_strv(s->manager->bus, p, "org.freedesktop.login1.Session", properties);
}

int session_send_lock(Session *s, bool lock) {
        _cleanup_free_ char *p = NULL;

        assert(s);

        if (!SESSION_CLASS_CAN_LOCK(s->class))
                return -ENOTTY;

        p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        return sd_bus_emit_signal(
                        s->manager->bus,
                        p,
                        "org.freedesktop.login1.Session",
                        lock ? "Lock" : "Unlock",
                        NULL);
}

int session_send_lock_all(Manager *m, bool lock) {
        Session *session;
        int r = 0;

        assert(m);

        HASHMAP_FOREACH(session, m->sessions) {

                if (!SESSION_CLASS_CAN_LOCK(session->class))
                        continue;

                RET_GATHER(r, session_send_lock(session, lock));
        }

        return r;
}

int session_send_create_reply_bus(Session *s, const sd_bus_error *error) {
        assert(s);

        /* This is called after the session scope and the user service were successfully created, and
         * finishes where manager_create_session() left off. */

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *c = TAKE_PTR(s->create_message);
        if (!c)
                return 0;

        if (sd_bus_error_is_set(error))
                return sd_bus_reply_method_error(c, error);

        /* Prior to v258, logind tracked sessions by installing a fifo in client and subscribe to its EOF.
         * Now we can fully rely on pidfd for this, but still need to return *something* to the client.
         * Allocate something lightweight and isolated as placeholder. */
        _cleanup_close_ int fd = eventfd(0, EFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        _cleanup_free_ char *p = session_bus_path(s);
        if (!p)
                return -ENOMEM;

        log_debug("Sending D-Bus reply about created session: "
                  "id=%s object_path=%s uid=" UID_FMT " runtime_path=%s seat=%s vtnr=%u",
                  s->id,
                  p,
                  s->user->user_record->uid,
                  s->user->runtime_path,
                  s->seat ? s->seat->id : "",
                  s->vtnr);

        return sd_bus_reply_method_return(
                        c, "soshusub",
                        s->id,
                        p,
                        s->user->runtime_path,
                        fd, /* not really used - see comments above */
                        (uint32_t) s->user->user_record->uid,
                        s->seat ? s->seat->id : "",
                        (uint32_t) s->vtnr,
                        false);
}

int session_send_upgrade_reply(Session *s, const sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *c = NULL;
        assert(s);

        if (!s->upgrade_message)
                return 0;

        /* See comments in session_send_create_reply */
        if (!sd_bus_error_is_set(error) && session_job_pending(s))
                return 0;

        c = TAKE_PTR(s->upgrade_message);
        if (error)
                return sd_bus_reply_method_error(c, error);

        session_save(s);

        return sd_bus_reply_method_return(c, NULL);
}

static const sd_bus_vtable session_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Id", "s", NULL, offsetof(Session, id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("User", "(uo)", property_get_user, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Name", "s", property_get_name, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        BUS_PROPERTY_DUAL_TIMESTAMP("Timestamp", offsetof(Session, timestamp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("VTNr", "u", NULL, offsetof(Session, vtnr), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Seat", "(so)", property_get_seat, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TTY", "s", NULL, offsetof(Session, tty), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Display", "s", NULL, offsetof(Session, display), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Remote", "b", bus_property_get_bool, offsetof(Session, remote), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemoteHost", "s", NULL, offsetof(Session, remote_host), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RemoteUser", "s", NULL, offsetof(Session, remote_user), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Service", "s", NULL, offsetof(Session, service), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Desktop", "s", NULL, offsetof(Session, desktop), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Scope", "s", NULL, offsetof(Session, scope), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Leader", "u", bus_property_get_pid, offsetof(Session, leader.pid), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LeaderPIDFDId", "t", bus_property_get_pidfdid, offsetof(Session, leader), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Audit", "u", NULL, offsetof(Session, audit_id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Type", "s", property_get_type, offsetof(Session, type), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Class", "s", property_get_class, offsetof(Session, class), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("Active", "b", property_get_active, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("State", "s", property_get_state, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleHint", "b", property_get_idle_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHint", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IdleSinceHintMonotonic", "t", property_get_idle_since_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanIdle", "b", property_get_can_idle, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CanLock", "b", property_get_can_lock, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LockedHint", "b", property_get_locked_hint, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD("Terminate",
                      NULL,
                      NULL,
                      bus_session_method_terminate,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Activate",
                      NULL,
                      NULL,
                      bus_session_method_activate,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Lock",
                      NULL,
                      NULL,
                      bus_session_method_lock,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Unlock",
                      NULL,
                      NULL,
                      bus_session_method_lock,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetIdleHint",
                                SD_BUS_ARGS("b", idle),
                                SD_BUS_NO_RESULT,
                                method_set_idle_hint,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLockedHint",
                                SD_BUS_ARGS("b", locked),
                                SD_BUS_NO_RESULT,
                                method_set_locked_hint,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Kill",
                                SD_BUS_ARGS("s", whom, "i", signal_number),
                                SD_BUS_NO_RESULT,
                                bus_session_method_kill,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TakeControl",
                                SD_BUS_ARGS("b", force),
                                SD_BUS_NO_RESULT,
                                method_take_control,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ReleaseControl",
                      NULL,
                      NULL,
                      method_release_control,
                      SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetType",
                                SD_BUS_ARGS("s", type),
                                SD_BUS_NO_RESULT,
                                method_set_type,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetClass",
                                SD_BUS_ARGS("s", class),
                                SD_BUS_NO_RESULT,
                                method_set_class,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetDisplay",
                                SD_BUS_ARGS("s", display),
                                SD_BUS_NO_RESULT,
                                method_set_display,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetTTY",
                                SD_BUS_ARGS("h", tty_fd),
                                SD_BUS_NO_RESULT,
                                method_set_tty,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("TakeDevice",
                                SD_BUS_ARGS("u", major, "u", minor),
                                SD_BUS_RESULT("h", fd, "b", inactive),
                                method_take_device,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ReleaseDevice",
                                SD_BUS_ARGS("u", major, "u", minor),
                                SD_BUS_NO_RESULT,
                                method_release_device,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("PauseDeviceComplete",
                                SD_BUS_ARGS("u", major, "u", minor),
                                SD_BUS_NO_RESULT,
                                method_pause_device_complete,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetBrightness",
                                SD_BUS_ARGS("s", subsystem, "s", name, "u", brightness),
                                SD_BUS_NO_RESULT,
                                method_set_brightness,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_SIGNAL_WITH_ARGS("PauseDevice",
                                SD_BUS_ARGS("u", major, "u", minor, "s", type),
                                0),
        SD_BUS_SIGNAL_WITH_ARGS("ResumeDevice",
                                SD_BUS_ARGS("u", major, "u", minor, "h", fd),
                                0),
        SD_BUS_SIGNAL("Lock", NULL, 0),
        SD_BUS_SIGNAL("Unlock", NULL, 0),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation session_object = {
        "/org/freedesktop/login1/session",
        "org.freedesktop.login1.Session",
        .fallback_vtables = BUS_FALLBACK_VTABLES({session_vtable, session_object_find}),
        .node_enumerator = session_node_enumerator,
};
