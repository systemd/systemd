/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-polkit.h"
#include "format-util.h"
#include "homed-bus.h"
#include "homed-home-bus.h"
#include "homed-manager-bus.h"
#include "homed-manager.h"
#include "strv.h"
#include "user-record-sign.h"
#include "user-record-util.h"
#include "user-util.h"

static int property_get_auto_login(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(sso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(h, m->homes_by_name) {
                _cleanup_strv_free_ char **seats = NULL;
                _cleanup_free_ char *home_path = NULL;

                r = home_auto_login(h, &seats);
                if (r < 0) {
                        log_debug_errno(r, "Failed to determine whether home '%s' is candidate for auto-login, ignoring: %m", h->user_name);
                        continue;
                }
                if (!r)
                        continue;

                r = bus_home_path(h, &home_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate home bus path: %m");

                STRV_FOREACH(s, seats) {
                        r = sd_bus_message_append(reply, "(sso)", h->user_name, *s, home_path);
                        if (r < 0)
                                return r;
                }
        }

        return sd_bus_message_close_container(reply);
}

static int method_get_home_by_name(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *path = NULL;
        const char *user_name;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &user_name);
        if (r < 0)
                return r;
        if (!valid_user_group_name(user_name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "User name %s is not valid", user_name);

        h = hashmap_get(m->homes_by_name, user_name);
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for user %s known", user_name);

        r = bus_home_path(h, &path);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(
                        message, "usussso",
                        (uint32_t) h->uid,
                        home_state_to_string(home_get_state(h)),
                        h->record ? (uint32_t) user_record_gid(h->record) : GID_INVALID,
                        h->record ? user_record_real_name(h->record) : NULL,
                        h->record ? user_record_home_directory(h->record) : NULL,
                        h->record ? user_record_shell(h->record) : NULL,
                        path);
}

static int method_get_home_by_uid(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *path = NULL;
        Manager *m = ASSERT_PTR(userdata);
        uint32_t uid;
        int r;
        Home *h;

        assert(message);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;
        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "UID " UID_FMT " is not valid", uid);

        h = hashmap_get(m->homes_by_uid, UID_TO_PTR(uid));
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for UID " UID_FMT " known", uid);

        /* Note that we don't use bus_home_path() here, but build the path manually, since if we are queried
         * for a UID we should also generate the bus path with a UID, and bus_home_path() uses our more
         * typical bus path by name. */
        if (asprintf(&path, "/org/freedesktop/home1/home/" UID_FMT, h->uid) < 0)
                return -ENOMEM;

        return sd_bus_reply_method_return(
                        message, "ssussso",
                        h->user_name,
                        home_state_to_string(home_get_state(h)),
                        h->record ? (uint32_t) user_record_gid(h->record) : GID_INVALID,
                        h->record ? user_record_real_name(h->record) : NULL,
                        h->record ? user_record_home_directory(h->record) : NULL,
                        h->record ? user_record_shell(h->record) : NULL,
                        path);
}

static int method_list_homes(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(message);

        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(susussso)");
        if (r < 0)
                return r;

        HASHMAP_FOREACH(h, m->homes_by_uid) {
                _cleanup_free_ char *path = NULL;

                r = bus_home_path(h, &path);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(
                                reply, "(susussso)",
                                h->user_name,
                                (uint32_t) h->uid,
                                home_state_to_string(home_get_state(h)),
                                h->record ? (uint32_t) user_record_gid(h->record) : GID_INVALID,
                                h->record ? user_record_real_name(h->record) : NULL,
                                h->record ? user_record_home_directory(h->record) : NULL,
                                h->record ? user_record_shell(h->record) : NULL,
                                path);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static int method_get_user_record_by_name(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *json = NULL, *path = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *user_name;
        bool incomplete;
        Home *h;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &user_name);
        if (r < 0)
                return r;
        if (!valid_user_group_name(user_name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "User name %s is not valid", user_name);

        h = hashmap_get(m->homes_by_name, user_name);
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for user %s known", user_name);

        r = bus_home_get_record_json(h, message, &json, &incomplete);
        if (r < 0)
                return r;

        r = bus_home_path(h, &path);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(
                        message, "sbo",
                        json,
                        incomplete,
                        path);
}

static int method_get_user_record_by_uid(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_free_ char *json = NULL, *path = NULL;
        Manager *m = ASSERT_PTR(userdata);
        bool incomplete;
        uint32_t uid;
        Home *h;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "u", &uid);
        if (r < 0)
                return r;
        if (!uid_is_valid(uid))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "UID " UID_FMT " is not valid", uid);

        h = hashmap_get(m->homes_by_uid, UID_TO_PTR(uid));
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for UID " UID_FMT " known", uid);

        r = bus_home_get_record_json(h, message, &json, &incomplete);
        if (r < 0)
                return r;

        if (asprintf(&path, "/org/freedesktop/home1/home/" UID_FMT, h->uid) < 0)
                return -ENOMEM;

        return sd_bus_reply_method_return(
                        message, "sbo",
                        json,
                        incomplete,
                        path);
}

static int generic_home_method(
                Manager *m,
                sd_bus_message *message,
                sd_bus_message_handler_t handler,
                sd_bus_error *error) {

        const char *user_name;
        Home *h;
        int r;

        assert(m);
        assert(message);
        assert(handler);

        r = sd_bus_message_read(message, "s", &user_name);
        if (r < 0)
                return r;

        if (!valid_user_group_name(user_name, 0))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "User name %s is not valid", user_name);

        h = hashmap_get(m->homes_by_name, user_name);
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for user %s known", user_name);

        return handler(message, h, error);
}

static int method_activate_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_activate, error);
}

static int method_deactivate_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_deactivate, error);
}

static int validate_and_allocate_home(Manager *m, UserRecord *hr, Home **ret, sd_bus_error *error) {
        _cleanup_(user_record_unrefp) UserRecord *signed_hr = NULL;
        struct passwd *pw;
        struct group *gr;
        bool signed_locally;
        Home *other;
        int r;

        assert(m);
        assert(hr);
        assert(ret);

        r = user_record_is_supported(hr, error);
        if (r < 0)
                return r;

        other = hashmap_get(m->homes_by_name, hr->user_name);
        if (other)
                return sd_bus_error_setf(error, BUS_ERROR_USER_NAME_EXISTS, "Specified user name %s exists already, refusing.", hr->user_name);

        pw = getpwnam(hr->user_name);
        if (pw)
                return sd_bus_error_setf(error, BUS_ERROR_USER_NAME_EXISTS, "Specified user name %s exists in the NSS user database, refusing.", hr->user_name);

        gr = getgrnam(hr->user_name);
        if (gr)
                return sd_bus_error_setf(error, BUS_ERROR_USER_NAME_EXISTS, "Specified user name %s conflicts with an NSS group by the same name, refusing.", hr->user_name);

        r = manager_verify_user_record(m, hr);
        switch (r) {

        case USER_RECORD_UNSIGNED:
                /* If the record is unsigned, then let's sign it with our own key */
                r = manager_sign_user_record(m, hr, &signed_hr, error);
                if (r < 0)
                        return r;

                hr = signed_hr;
                _fallthrough_;

        case USER_RECORD_SIGNED_EXCLUSIVE:
                signed_locally = true;
                break;

        case USER_RECORD_SIGNED:
        case USER_RECORD_FOREIGN:
                signed_locally = false;
                break;

        case -ENOKEY:
                return sd_bus_error_setf(error, BUS_ERROR_BAD_SIGNATURE, "Specified user record for %s is signed by a key we don't recognize, refusing.", hr->user_name);

        default:
                return sd_bus_error_set_errnof(error, r, "Failed to validate signature for '%s': %m", hr->user_name);
        }

        if (uid_is_valid(hr->uid)) {
                other = hashmap_get(m->homes_by_uid, UID_TO_PTR(hr->uid));
                if (other)
                        return sd_bus_error_setf(error, BUS_ERROR_UID_IN_USE, "Specified UID " UID_FMT " already in use by home %s, refusing.", hr->uid, other->user_name);

                pw = getpwuid(hr->uid);
                if (pw)
                        return sd_bus_error_setf(error, BUS_ERROR_UID_IN_USE, "Specified UID " UID_FMT " already in use by NSS user %s, refusing.", hr->uid, pw->pw_name);

                gr = getgrgid(hr->uid);
                if (gr)
                        return sd_bus_error_setf(error, BUS_ERROR_UID_IN_USE, "Specified UID " UID_FMT " already in use as GID by NSS group %s, refusing.", hr->uid, gr->gr_name);
        } else {
                r = manager_augment_record_with_uid(m, hr);
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to acquire UID for '%s': %m", hr->user_name);
        }

        r = home_new(m, hr, NULL, ret);
        if (r < 0)
                return r;

        (*ret)->signed_locally = signed_locally;
        return r;
}

static int method_register_home(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(home_freep) Home *h = NULL;
        int r;

        assert(message);

        r = bus_message_read_home_record(message, USER_RECORD_LOAD_EMBEDDED|USER_RECORD_PERMISSIVE, &hr, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.create-home",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = validate_and_allocate_home(m, hr, &h, error);
        if (r < 0)
                return r;

        r = home_save_record(h);
        if (r < 0)
                return r;

        TAKE_PTR(h);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unregister_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_unregister, error);
}

static int method_create_home(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(message);

        r = bus_message_read_home_record(message, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE, &hr, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.create-home",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        r = validate_and_allocate_home(m, hr, &h, error);
        if (r < 0)
                return r;

        r = home_create(h, hr, error);
        if (r < 0)
                goto fail;

        assert(r == 0);
        h->unregister_on_failure = true;
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        return 1;

fail:
        (void) home_unlink_record(h);
        h = home_free(h);
        return r;
}

static int method_realize_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_realize, error);
}

static int method_remove_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_remove, error);
}

static int method_fixate_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_fixate, error);
}

static int method_authenticate_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_authenticate, error);
}

static int method_update_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(message);

        r = bus_message_read_home_record(message, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE, &hr, error);
        if (r < 0)
                return r;

        assert(hr->user_name);

        h = hashmap_get(m->homes_by_name, hr->user_name);
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for user %s known", hr->user_name);

        return bus_home_method_update_record(h, message, hr, error);
}

static int method_resize_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_resize, error);
}

static int method_change_password_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_change_password, error);
}

static int method_lock_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_lock, error);
}

static int method_unlock_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_unlock, error);
}

static int method_acquire_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_acquire, error);
}

static int method_ref_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_ref, error);
}

static int method_release_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_release, error);
}

static int method_lock_all_homes(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(operation_unrefp) Operation *o = NULL;
        bool waiting = false;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        /* This is called from logind when we are preparing for system suspend. We enqueue a lock operation
         * for every suitable home we have and only when all of them completed we send a reply indicating
         * completion. */

        HASHMAP_FOREACH(h, m->homes_by_name) {

                /* Automatically suspend all homes that have at least one client referencing it that asked
                 * for "please suspend", and no client that asked for "please do not suspend". */
                if (h->ref_event_source_dont_suspend ||
                    !h->ref_event_source_please_suspend)
                        continue;

                if (!o) {
                        o = operation_new(OPERATION_LOCK_ALL, message);
                        if (!o)
                                return -ENOMEM;
                }

                log_info("Automatically locking home of user %s.", h->user_name);

                r = home_schedule_operation(h, o, error);
                if (r < 0)
                        return r;

                waiting = true;
        }

        if (waiting) /* At least one lock operation was enqeued, let's leave here without a reply: it will
                      * be sent as soon as the last of the lock operations completed. */
                return 1;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_deactivate_all_homes(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(operation_unrefp) Operation *o = NULL;
        bool waiting = false;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        /* This is called from systemd-homed-activate.service's ExecStop= command to ensure that all home
         * directories are shutdown before the system goes down. Note that we don't do this from
         * systemd-homed.service itself since we want to allow restarting of it without tearing down all home
         * directories. */

        HASHMAP_FOREACH(h, m->homes_by_name) {

                if (!o) {
                        o = operation_new(OPERATION_DEACTIVATE_ALL, message);
                        if (!o)
                                return -ENOMEM;
                }

                log_info("Automatically deactivating home of user %s.", h->user_name);

                r = home_schedule_operation(h, o, error);
                if (r < 0)
                        return r;

                waiting = true;
        }

        if (waiting) /* At least one lock operation was enqeued, let's leave here without a reply: it will be
                      * sent as soon as the last of the deactivation operations completed. */
                return 1;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_rebalance(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = manager_schedule_rebalance(m, /* immediately= */ true);
        if (r == 0)
                return sd_bus_reply_method_errorf(message, BUS_ERROR_REBALANCE_NOT_NEEDED, "No home directories need rebalancing.");
        if (r < 0)
                return r;

        /* Keep a reference to this message, so that we can reply to it once we are done */
        r = set_ensure_put(&m->rebalance_queued_method_calls, &bus_message_hash_ops, message);
        if (r < 0)
                return log_error_errno(r, "Failed to track rebalance bus message: %m");

        sd_bus_message_ref(message);
        return 1;
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("AutoLogin", "a(sso)", property_get_auto_login, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD_WITH_ARGS("GetHomeByName",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_RESULT("u", uid,
                                              "s", home_state,
                                              "u", gid,
                                              "s", real_name,
                                              "s", home_directory,
                                              "s", shell,
                                              "o", bus_path),
                                method_get_home_by_name,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetHomeByUID",
                                SD_BUS_ARGS("u", uid),
                                SD_BUS_RESULT("s", user_name,
                                              "s", home_state,
                                              "u", gid,
                                              "s", real_name,
                                              "s", home_directory,
                                              "s", shell,
                                              "o", bus_path),
                                method_get_home_by_uid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetUserRecordByName",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_RESULT("s", user_record, "b", incomplete, "o", bus_path),
                                method_get_user_record_by_name,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("GetUserRecordByUID",
                                SD_BUS_ARGS("u", uid),
                                SD_BUS_RESULT("s", user_record, "b", incomplete, "o", bus_path),
                                method_get_user_record_by_uid,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("ListHomes",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(susussso)", home_areas),
                                method_list_homes,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        /* The following methods directly execute an operation on a home area, without ref-counting, queueing
         * or anything, and are accessible through homectl. */
        SD_BUS_METHOD_WITH_ARGS("ActivateHome",
                                SD_BUS_ARGS("s", user_name, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_activate_home,
                                SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("DeactivateHome",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_NO_RESULT,
                                method_deactivate_home,
                                0),

        /* Add the JSON record to homed, but don't create actual $HOME */
        SD_BUS_METHOD_WITH_ARGS("RegisterHome",
                                SD_BUS_ARGS("s", user_record),
                                SD_BUS_NO_RESULT,
                                method_register_home,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        /* Remove the JSON record from homed, but don't remove actual $HOME  */
        SD_BUS_METHOD_WITH_ARGS("UnregisterHome",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_NO_RESULT,
                                method_unregister_home,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        /* Add JSON record, and create $HOME for it */
        SD_BUS_METHOD_WITH_ARGS("CreateHome",
                                SD_BUS_ARGS("s", user_record),
                                SD_BUS_NO_RESULT,
                                method_create_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        /* Create $HOME for already registered JSON entry */
        SD_BUS_METHOD_WITH_ARGS("RealizeHome",
                                SD_BUS_ARGS("s", user_name, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_realize_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        /* Remove the JSON record and remove $HOME */
        SD_BUS_METHOD_WITH_ARGS("RemoveHome",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_NO_RESULT,
                                method_remove_home,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        /* Investigate $HOME and propagate contained JSON record into our database */
        SD_BUS_METHOD_WITH_ARGS("FixateHome",
                                SD_BUS_ARGS("s", user_name, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_fixate_home,
                                SD_BUS_VTABLE_SENSITIVE),

        /* Just check credentials */
        SD_BUS_METHOD_WITH_ARGS("AuthenticateHome",
                                SD_BUS_ARGS("s", user_name, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_authenticate_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        /* Update the JSON record of existing user */
        SD_BUS_METHOD_WITH_ARGS("UpdateHome",
                                SD_BUS_ARGS("s", user_record),
                                SD_BUS_NO_RESULT,
                                method_update_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        SD_BUS_METHOD_WITH_ARGS("ResizeHome",
                                SD_BUS_ARGS("s", user_name, "t", size, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_resize_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        SD_BUS_METHOD_WITH_ARGS("ChangePasswordHome",
                                SD_BUS_ARGS("s", user_name, "s", new_secret, "s", old_secret),
                                SD_BUS_NO_RESULT,
                                method_change_password_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),

        /* Prepare active home for system suspend: flush out passwords, suspend access */
        SD_BUS_METHOD_WITH_ARGS("LockHome",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_NO_RESULT,
                                method_lock_home,
                                0),

        /* Make $HOME usable after system resume again */
        SD_BUS_METHOD_WITH_ARGS("UnlockHome",
                                SD_BUS_ARGS("s", user_name, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_unlock_home,
                                SD_BUS_VTABLE_SENSITIVE),

        /* The following methods implement ref-counted activation, and are what the PAM module and "homectl
         * with" use. In contrast to the methods above which fail if an operation is already being executed
         * on a home directory, these ones will queue the request, and are thus more reliable. Moreover,
         * they are a bit smarter: AcquireHome() will fixate, activate, unlock, or authenticate depending on
         * the state of the home area, so that the end result is always the same (i.e. the home directory is
         * accessible), and we always validate the specified passwords. RefHome() will not authenticate, and
         * thus only works if the home area is already active. */
        SD_BUS_METHOD_WITH_ARGS("AcquireHome",
                                SD_BUS_ARGS("s", user_name, "s", secret, "b", please_suspend),
                                SD_BUS_RESULT("h", send_fd),
                                method_acquire_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("RefHome",
                                SD_BUS_ARGS("s", user_name, "b", please_suspend),
                                SD_BUS_RESULT("h", send_fd),
                                method_ref_home,
                                0),
        SD_BUS_METHOD_WITH_ARGS("ReleaseHome",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_NO_RESULT,
                                method_release_home,
                                0),

        /* An operation that acts on all homes that allow it */
        SD_BUS_METHOD("LockAllHomes", NULL, NULL, method_lock_all_homes, 0),
        SD_BUS_METHOD("DeactivateAllHomes", NULL, NULL, method_deactivate_all_homes, 0),
        SD_BUS_METHOD("Rebalance", NULL, NULL, method_rebalance, 0),

        SD_BUS_VTABLE_END
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/home1",
        "org.freedesktop.home1.Manager",
        .vtables = BUS_VTABLES(manager_vtable),
        .children = BUS_IMPLEMENTATIONS(&home_object),
};

static int on_deferred_auto_login(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        m->deferred_auto_login_event_source = sd_event_source_disable_unref(m->deferred_auto_login_event_source);

        r = sd_bus_emit_properties_changed(
                        m->bus,
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "AutoLogin", NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to send AutoLogin property change event, ignoring: %m");

        return 0;
}

int bus_manager_emit_auto_login_changed(Manager *m) {
        int r;
        assert(m);

        if (m->deferred_auto_login_event_source)
                return 0;

        if (!m->event)
                return 0;

        if (IN_SET(sd_event_get_state(m->event), SD_EVENT_FINISHED, SD_EVENT_EXITING))
                return 0;

        r = sd_event_add_defer(m->event, &m->deferred_auto_login_event_source, on_deferred_auto_login, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate auto login event source: %m");

        r = sd_event_source_set_priority(m->deferred_auto_login_event_source, SD_EVENT_PRIORITY_IDLE+10);
        if (r < 0)
                log_warning_errno(r, "Failed to tweak priority of event source, ignoring: %m");

        (void) sd_event_source_set_description(m->deferred_auto_login_event_source, "deferred-auto-login");
        return 1;
}
