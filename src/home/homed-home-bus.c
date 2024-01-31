/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "bus-common-errors.h"
#include "bus-polkit.h"
#include "fd-util.h"
#include "homed-bus.h"
#include "homed-home-bus.h"
#include "homed-home.h"
#include "strv.h"
#include "user-record-util.h"
#include "user-util.h"

static int property_get_unix_record(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Home *h = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(
                        reply, "(suusss)",
                        h->user_name,
                        (uint32_t) h->uid,
                        h->record ? (uint32_t) user_record_gid(h->record) : GID_INVALID,
                        h->record ? user_record_real_name(h->record) : NULL,
                        h->record ? user_record_home_directory(h->record) : NULL,
                        h->record ? user_record_shell(h->record) : NULL);
}

static int property_get_state(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Home *h = ASSERT_PTR(userdata);

        assert(bus);
        assert(reply);

        return sd_bus_message_append(reply, "s", home_state_to_string(home_get_state(h)));
}

int bus_home_client_is_trusted(Home *h, sd_bus_message *message) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t euid;
        int r;

        assert(h);

        if (!message)
                return -EINVAL;

        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_euid(creds, &euid);
        if (r < 0)
                return r;

        return euid == 0 || h->uid == euid;
}

int bus_home_get_record_json(
                Home *h,
                sd_bus_message *message,
                char **ret,
                bool *ret_incomplete) {

        _cleanup_(user_record_unrefp) UserRecord *augmented = NULL;
        UserRecordLoadFlags flags;
        int r, trusted;

        assert(h);
        assert(ret);

        trusted = bus_home_client_is_trusted(h, message);
        if (trusted < 0) {
                log_warning_errno(trusted, "Failed to determine whether client is trusted, assuming untrusted.");
                trusted = false;
        }

        flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_BINDING|USER_RECORD_STRIP_SECRET|USER_RECORD_ALLOW_STATUS|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE;
        if (trusted)
                flags |= USER_RECORD_ALLOW_PRIVILEGED;
        else
                flags |= USER_RECORD_STRIP_PRIVILEGED;

        r = home_augment_status(h, flags, &augmented);
        if (r < 0)
                return r;

        r = json_variant_format(augmented->json, 0, ret);
        if (r < 0)
                return r;

        if (ret_incomplete)
                *ret_incomplete = augmented->incomplete;

        return 0;
}

static int property_get_user_record(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *json = NULL;
        Home *h = ASSERT_PTR(userdata);
        bool incomplete;
        int r;

        assert(bus);
        assert(reply);

        r = bus_home_get_record_json(h, sd_bus_get_current_message(bus), &json, &incomplete);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "(sb)", json, incomplete);
}

int bus_home_method_activate(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = home_activate(h, secret, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        /* The operation is now in process, keep track of this message so that we can later reply to it. */
        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_deactivate(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = home_deactivate(h, false, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_unregister(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.remove-home",
                        /* details= */ NULL,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_unregister(h, error);
        if (r < 0)
                return r;

        assert(r > 0);

        /* Note that home_unregister() destroyed 'h' here, so no more accesses */

        return sd_bus_reply_method_return(message, NULL);
}

int bus_home_method_realize(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.create-home",
                        /* details= */ NULL,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_create(h, secret, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        h->unregister_on_failure = false;

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_remove(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.remove-home",
                        /* details= */ NULL,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_remove(h, error);
        if (r < 0)
                return r;
        if (r > 0) /* Done already. Note that home_remove() destroyed 'h' here, so no more accesses */
                return sd_bus_reply_method_return(message, NULL);

        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_fixate(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = home_fixate(h, secret, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_authenticate(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.home1.authenticate-home",
                        /* details= */ NULL,
                        /* interactive= */ false,
                        h->uid,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_authenticate(h, secret, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_update_record(Home *h, sd_bus_message *message, UserRecord *hr, sd_bus_error *error) {
        int r;

        assert(h);
        assert(message);
        assert(hr);

        r = user_record_is_supported(hr, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.update-home",
                        /* details= */ NULL,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_update(h, hr, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_update(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_home_record(message, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE, &hr, error);
        if (r < 0)
                return r;

        return bus_home_method_update_record(h, message, hr, error);
}

int bus_home_method_resize(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        uint64_t sz;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "t", &sz);
        if (r < 0)
                return r;

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.resize-home",
                        /* details= */ NULL,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_resize(h, sz, secret, /* automatic= */ false, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_change_password(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *new_secret = NULL, *old_secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_secret(message, &new_secret, error);
        if (r < 0)
                return r;

        r = bus_message_read_secret(message, &old_secret, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async_full(
                        message,
                        "org.freedesktop.home1.passwd-home",
                        /* details= */ NULL,
                        /* interactive= */ false,
                        h->uid,
                        &h->manager->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = home_passwd(h, new_secret, old_secret, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_lock(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = home_lock(h, error);
        if (r < 0)
                return r;
        if (r > 0) /* Done */
                return sd_bus_reply_method_return(message, NULL);

        /* The operation is now in process, keep track of this message so that we can later reply to it. */
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_unlock(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = home_unlock(h, secret, error);
        if (r < 0)
                return r;

        assert(r == 0);
        assert(!h->current_operation);

        /* The operation is now in process, keep track of this message so that we can later reply to it. */
        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_acquire(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        _cleanup_(operation_unrefp) Operation *o = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r, please_suspend;
        Home *h = ASSERT_PTR(userdata);

        assert(message);

        r = bus_message_read_secret(message, &secret, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(message, "b", &please_suspend);
        if (r < 0)
                return r;

        /* This operation might not be something we can executed immediately, hence queue it */
        fd = home_create_fifo(h, please_suspend);
        if (fd < 0)
                return sd_bus_reply_method_errnof(message, fd, "Failed to allocate FIFO for %s: %m", h->user_name);

        o = operation_new(OPERATION_ACQUIRE, message);
        if (!o)
                return -ENOMEM;

        o->secret = TAKE_PTR(secret);
        o->send_fd = TAKE_FD(fd);

        r = home_schedule_operation(h, o, error);
        if (r < 0)
                return r;

        return 1;
}

int bus_home_method_ref(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_close_ int fd = -EBADF;
        Home *h = ASSERT_PTR(userdata);
        HomeState state;
        int please_suspend, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &please_suspend);
        if (r < 0)
                return r;

        state = home_get_state(h);
        switch (state) {
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_UNFIXATED:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_NOT_ACTIVE, "Home %s not active.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        default:
                if (HOME_STATE_IS_ACTIVE(state))
                        break;

                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        fd = home_create_fifo(h, please_suspend);
        if (fd < 0)
                return sd_bus_reply_method_errnof(message, fd, "Failed to allocate FIFO for %s: %m", h->user_name);

        return sd_bus_reply_method_return(message, "h", fd);
}

int bus_home_method_release(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(operation_unrefp) Operation *o = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        assert(message);

        o = operation_new(OPERATION_RELEASE, message);
        if (!o)
                return -ENOMEM;

        r = home_schedule_operation(h, o, error);
        if (r < 0)
                return r;

        return 1;
}

/* We map a uid_t as uint32_t bus property, let's ensure this is safe. */
assert_cc(sizeof(uid_t) == sizeof(uint32_t));

int bus_home_path(Home *h, char **ret) {
        assert(ret);

        return sd_bus_path_encode("/org/freedesktop/home1/home", h->user_name, ret);
}

static int bus_home_object_find(
                sd_bus *bus,
                const char *path,
                const char *interface,
                void *userdata,
                void **found,
                sd_bus_error *error) {

        _cleanup_free_ char *e = NULL;
        Manager *m = userdata;
        uid_t uid;
        Home *h;
        int r;

        r = sd_bus_path_decode(path, "/org/freedesktop/home1/home", &e);
        if (r <= 0)
                return 0;

        if (parse_uid(e, &uid) >= 0)
                h = hashmap_get(m->homes_by_uid, UID_TO_PTR(uid));
        else
                h = hashmap_get(m->homes_by_name, e);
        if (!h)
                return 0;

        *found = h;
        return 1;
}

static int bus_home_node_enumerator(
                sd_bus *bus,
                const char *path,
                void *userdata,
                char ***nodes,
                sd_bus_error *error) {

        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        size_t k = 0;
        Home *h;
        int r;

        assert(nodes);

        l = new0(char*, hashmap_size(m->homes_by_uid) + 1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(h, m->homes_by_uid) {
                r = bus_home_path(h, l + k);
                if (r < 0)
                        return r;

                k++;
        }

        *nodes = TAKE_PTR(l);
        return 1;
}

const sd_bus_vtable home_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("UserName", "s",
                        NULL, offsetof(Home, user_name),
                        SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UID", "u",
                        NULL, offsetof(Home, uid),
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("UnixRecord", "(suusss)",
                        property_get_unix_record, 0,
                        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("State", "s",
                        property_get_state, 0,
                        0),
        SD_BUS_PROPERTY("UserRecord", "(sb)",
                        property_get_user_record, 0,
                        SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION|SD_BUS_VTABLE_SENSITIVE),

        SD_BUS_METHOD_WITH_ARGS("Activate",
                                SD_BUS_ARGS("s", secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_activate,
                                SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD("Deactivate", NULL, NULL, bus_home_method_deactivate, 0),
        SD_BUS_METHOD("Unregister", NULL, NULL, bus_home_method_unregister, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Realize",
                                SD_BUS_ARGS("s", secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_realize,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        SD_BUS_METHOD("Remove", NULL, NULL, bus_home_method_remove, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("Fixate",
                                SD_BUS_ARGS("s", secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_fixate,
                                SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("Authenticate",
                                SD_BUS_ARGS("s", secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_authenticate,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("Update",
                                SD_BUS_ARGS("s", user_record),
                                SD_BUS_NO_RESULT,
                                bus_home_method_update,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("Resize",
                                SD_BUS_ARGS("t", size, "s", secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_resize,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("ChangePassword",
                                SD_BUS_ARGS("s", new_secret, "s", old_secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_change_password,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD("Lock", NULL, NULL, bus_home_method_lock, 0),
        SD_BUS_METHOD_WITH_ARGS("Unlock",
                                SD_BUS_ARGS("s", secret),
                                SD_BUS_NO_RESULT,
                                bus_home_method_unlock,
                                SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("Acquire",
                                SD_BUS_ARGS("s", secret, "b", please_suspend),
                                SD_BUS_RESULT("h", send_fd),
                                bus_home_method_acquire,
                                SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("Ref",
                                SD_BUS_ARGS("b", please_suspend),
                                SD_BUS_RESULT("h", send_fd),
                                bus_home_method_ref,
                                0),
        SD_BUS_METHOD("Release", NULL, NULL, bus_home_method_release, 0),
        SD_BUS_VTABLE_END
};

const BusObjectImplementation home_object = {
        "/org/freedesktop/home1/home",
        "org.freedesktop.home1.Home",
        .fallback_vtables = BUS_FALLBACK_VTABLES({home_vtable, bus_home_object_find}),
        .node_enumerator = bus_home_node_enumerator,
        .manager = true,
};

static int on_deferred_change(sd_event_source *s, void *userdata) {
        _cleanup_free_ char *path = NULL;
        Home *h = ASSERT_PTR(userdata);
        int r;

        h->deferred_change_event_source = sd_event_source_disable_unref(h->deferred_change_event_source);

        r = bus_home_path(h, &path);
        if (r < 0) {
                log_warning_errno(r, "Failed to generate home bus path, ignoring: %m");
                return 0;
        }

        if (h->announced)
                r = sd_bus_emit_properties_changed_strv(h->manager->bus, path, "org.freedesktop.home1.Home", NULL);
        else
                r = sd_bus_emit_object_added(h->manager->bus, path);
        if (r < 0)
                log_warning_errno(r, "Failed to send home change event, ignoring: %m");
        else
                h->announced = true;

        return 0;
}

int bus_home_emit_change(Home *h) {
        int r;

        assert(h);

        if (h->deferred_change_event_source)
                return 1;

        if (!h->manager->event)
                return 0;

        if (IN_SET(sd_event_get_state(h->manager->event), SD_EVENT_FINISHED, SD_EVENT_EXITING))
                return 0;

        r = sd_event_add_defer(h->manager->event, &h->deferred_change_event_source, on_deferred_change, h);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate deferred change event source: %m");

        r = sd_event_source_set_priority(h->deferred_change_event_source, SD_EVENT_PRIORITY_IDLE+5);
        if (r < 0)
                log_warning_errno(r, "Failed to tweak priority of event source, ignoring: %m");

        (void) sd_event_source_set_description(h->deferred_change_event_source, "deferred-change-event");
        return 1;
}

int bus_home_emit_remove(Home *h) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(h);

        if (!h->announced)
                return 0;

        if (!h->manager)
                return 0;

        if (!h->manager->bus)
                return 0;

        r = bus_home_path(h, &path);
        if (r < 0)
                return r;

        r = sd_bus_emit_object_removed(h->manager->bus, path);
        if (r < 0)
                return r;

        h->announced = false;
        return 1;
}
