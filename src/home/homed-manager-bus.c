/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-message-util.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "fileio.h"
#include "format-util.h"
#include "home-util.h"
#include "homed-bus.h"
#include "homed-home-bus.h"
#include "homed-home.h"
#include "homed-manager.h"
#include "homed-manager-bus.h"
#include "homed-operation.h"
#include "log.h"
#include "openssl-util.h"
#include "path-util.h"
#include "set.h"
#include "string-util.h"
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

        HASHMAP_FOREACH(h, m->homes_by_uid) {
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

static int lookup_user_name(
                Manager *m,
                sd_bus_message *message,
                const char *user_name,
                sd_bus_error *error,
                Home **ret) {

        Home *h;
        int r;

        assert(m);
        assert(message);
        assert(user_name);
        assert(ret);

        if (isempty(user_name)) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                uid_t uid;

                /* If an empty user name is specified, then identify caller's EUID and find home by that. */

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_euid(creds, &uid);
                if (r < 0)
                        return r;

                h = hashmap_get(m->homes_by_uid, UID_TO_PTR(uid));
                if (!h)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "Client's UID " UID_FMT " not managed.", uid);

        } else {
                r = manager_get_home_by_name(m, user_name, &h);
                if (r < 0)
                        return r;
                if (!h)
                        return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for user %s known", user_name);
        }

        *ret = h;
        return 0;
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

        r = lookup_user_name(m, message, user_name, error, &h);
        if (r < 0)
                return r;

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

        return sd_bus_message_send(reply);
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

        r = lookup_user_name(m, message, user_name, error, &h);
        if (r < 0)
                return r;

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

        r = lookup_user_name(m, message, user_name, error, &h);
        if (r < 0)
                return r;

        return handler(message, h, error);
}

static int method_activate_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_activate, error);
}

static int method_deactivate_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_deactivate, error);
}

static int check_for_conflicts(Manager *m, const char *name, sd_bus_error *error) {
        int r;

        assert(m);
        assert(name);

        Home *other = hashmap_get(m->homes_by_name, name);
        if (other)
                return sd_bus_error_setf(error, BUS_ERROR_USER_NAME_EXISTS, "Specified user name %s exists already, refusing.", name);

        r = getpwnam_malloc(name, /* ret= */ NULL);
        if (r >= 0)
                return sd_bus_error_setf(error, BUS_ERROR_USER_NAME_EXISTS, "Specified user name %s exists in the NSS user database, refusing.", name);
        if (r != -ESRCH)
                return r;

        r = getgrnam_malloc(name, /* ret= */ NULL);
        if (r >= 0)
                return sd_bus_error_setf(error, BUS_ERROR_USER_NAME_EXISTS, "Specified user name %s conflicts with an NSS group by the same name, refusing.", name);
        if (r != -ESRCH)
                return r;

        return 0;
}

static int validate_and_allocate_home(Manager *m, UserRecord *hr, Hashmap *blobs, Home **ret, sd_bus_error *error) {
        _cleanup_(user_record_unrefp) UserRecord *signed_hr = NULL;
        bool signed_locally;
        Home *other;
        int r;

        assert(m);
        assert(hr);
        assert(ret);

        r = user_record_is_supported(hr, error);
        if (r < 0)
                return r;

        r = check_for_conflicts(m, hr->user_name, error);
        if (r < 0)
                return r;

        if (hr->realm) {
                r = check_for_conflicts(m, user_record_user_name_and_realm(hr), error);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(a, hr->aliases) {
                r = check_for_conflicts(m, *a, error);
                if (r < 0)
                        return r;

                if (hr->realm) {
                        _cleanup_free_ char *alias_with_realm = NULL;
                        alias_with_realm = strjoin(*a, "@", hr->realm);
                        if (!alias_with_realm)
                                return -ENOMEM;

                        r = check_for_conflicts(m, alias_with_realm, error);
                        if (r < 0)
                                return r;
                }
        }

        if (blobs) {
                const char *failed = NULL;
                r = user_record_ensure_blob_manifest(hr, blobs, &failed);
                if (r == -EINVAL)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Provided blob files do not correspond to blob manifest.");
                if (r < 0)
                        return sd_bus_error_set_errnof(error, r, "Failed to generate hash for blob %s: %m", strnull(failed));
        }

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
                _cleanup_free_ struct passwd *pw = NULL;
                _cleanup_free_ struct group *gr = NULL;

                other = hashmap_get(m->homes_by_uid, UID_TO_PTR(hr->uid));
                if (other)
                        return sd_bus_error_setf(error, BUS_ERROR_UID_IN_USE, "Specified UID " UID_FMT " already in use by home %s, refusing.", hr->uid, other->user_name);

                r = getpwuid_malloc(hr->uid, &pw);
                if (r >= 0)
                        return sd_bus_error_setf(error, BUS_ERROR_UID_IN_USE, "Specified UID " UID_FMT " already in use by NSS user %s, refusing.", hr->uid, pw->pw_name);
                if (r != -ESRCH)
                        return r;

                r = getgrgid_malloc(hr->uid, &gr);
                if (r >= 0)
                        return sd_bus_error_setf(error, BUS_ERROR_UID_IN_USE, "Specified UID " UID_FMT " already in use as GID by NSS group %s, refusing.", hr->uid, gr->gr_name);
                if (r != -ESRCH)
                        return r;
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

        r = bus_message_read_home_record(message, USER_RECORD_EXTRACT_EMBEDDED|USER_RECORD_PERMISSIVE, &hr, error);
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

        r = validate_and_allocate_home(m, hr, NULL, &h, error);
        if (r < 0)
                return r;

        r = home_save_record(h);
        if (r < 0)
                return r;

        TAKE_PTR(h);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_adopt_home(
                sd_bus_message *message,
                void *userdata,
                sd_bus_error *error) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        const char *image_path = NULL;
        uint64_t flags = 0;
        r = sd_bus_message_read(message, "st", &image_path, &flags);
        if (r < 0)
                return r;

        if (!path_is_absolute(image_path) || !path_is_safe(image_path))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified path is not absolute or not valid: %s", image_path);
        if (flags != 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Flags field must be zero.");

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

        r = manager_adopt_home(m, image_path);
        if (r == -EMEDIUMTYPE)
                return sd_bus_error_setf(error, BUS_ERROR_UNRECOGNIZED_HOME_FORMAT, "Unrecognized format of home directory: %s", image_path);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static int method_unregister_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return generic_home_method(userdata, message, bus_home_method_unregister, error);
}

static int method_create_home(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        _cleanup_hashmap_free_ Hashmap *blobs = NULL;
        uint64_t flags = 0;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(message);

        r = bus_message_read_home_record(message, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE, &hr, error);
        if (r < 0)
                return r;

        if (endswith(sd_bus_message_get_member(message), "Ex")) {
                r = bus_message_read_blobs(message, &blobs, error);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(message, "t", &flags);
                if (r < 0)
                        return r;
                if ((flags & ~SD_HOMED_CREATE_FLAGS_ALL) != 0)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid flags provided.");
        }

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

        r = validate_and_allocate_home(m, hr, blobs, &h, error);
        if (r < 0)
                return r;

        r = home_create(h, hr, blobs, flags, error);
        if (r < 0)
                goto fail;

        assert(r == 0);
        h->unregister_on_failure = true;
        assert(!h->current_operation);

        r = home_set_current_message(h, message);
        if (r < 0)
                return r;

        h->current_operation->call_flags = flags;

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
        _cleanup_hashmap_free_ Hashmap *blobs = NULL;
        uint64_t flags = 0;
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(message);

        r = bus_message_read_home_record(message, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE, &hr, error);
        if (r < 0)
                return r;

        if (endswith(sd_bus_message_get_member(message), "Ex")) {
                r = bus_message_read_blobs(message, &blobs, error);
                if (r < 0)
                        return r;

                r = sd_bus_message_read(message, "t", &flags);
                if (r < 0)
                        return r;
        }

        assert(hr->user_name);

        h = hashmap_get(m->homes_by_name, hr->user_name);
        if (!h)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_HOME, "No home for user %s known", hr->user_name);

        return bus_home_update_record(h, message, hr, blobs, flags, error);
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

        HASHMAP_FOREACH(h, m->homes_by_uid) {

                if (!home_shall_suspend(h))
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

        HASHMAP_FOREACH(h, m->homes_by_uid) {

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
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_reply_method_errorf(message, BUS_ERROR_REBALANCE_NOT_NEEDED, "No home directories need rebalancing.");

        /* Keep a reference to this message, so that we can reply to it once we are done */
        r = set_ensure_consume(&m->rebalance_queued_method_calls, &bus_message_hash_ops, sd_bus_message_ref(message));
        if (r < 0)
                return log_error_errno(r, "Failed to track rebalance bus message: %m");
        assert(r > 0);

        return 1;
}

static int method_list_signing_keys(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(sst)");
        if (r < 0)
                return r;

        /* Add our own key pair first */
        r = manager_acquire_key_pair(m);
        if (r < 0)
                return r;

        _cleanup_free_ char *pem = NULL;
        r = openssl_pubkey_to_pem(m->private_key, &pem);
        if (r < 0)
                return log_error_errno(r, "Failed to convert public key to PEM: %m");

        r = sd_bus_message_append(
                        reply,
                        "(sst)",
                        "local.public",
                        pem,
                        UINT64_C(0));
        if (r < 0)
                return r;

        /* And then all public keys we recognize */
        EVP_PKEY *pkey;
        const char *fn;
        HASHMAP_FOREACH_KEY(pkey, fn, m->public_keys) {
                pem = mfree(pem);
                r = openssl_pubkey_to_pem(pkey, &pem);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert public key to PEM: %m");

                r = sd_bus_message_append(
                                reply,
                                "(sst)",
                                fn,
                                pem,
                                UINT64_C(0));
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_close_container(reply);
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static int method_get_signing_key(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        const char *fn;
        r = sd_bus_message_read(message, "s", &fn);
        if (r < 0)
                return r;

        /* Make sure the local key is loaded. */
        r = manager_acquire_key_pair(m);
        if (r < 0)
                return r;

        EVP_PKEY *pkey;

        if (streq(fn, "local.public"))
                pkey = m->private_key;
        else
                pkey = hashmap_get(m->public_keys, fn);
        if (!pkey)
                return sd_bus_error_setf(error, BUS_ERROR_NO_SUCH_KEY, "No key with name: %s", fn);

        _cleanup_free_ char *pem = NULL;
        r = openssl_pubkey_to_pem(pkey, &pem);
        if (r < 0)
                return log_error_errno(r, "Failed to convert public key to PEM: %m");

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = sd_bus_message_new_method_return(message, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append(
                        reply,
                        "st",
                        pem,
                        UINT64_C(0));
        if (r < 0)
                return r;

        return sd_bus_message_send(reply);
}

static bool valid_public_key_name(const char *fn) {
        assert(fn);

        /* Checks if the specified name is valid to export, i.e. is a filename, ends in ".public". */

        if (!filename_is_valid(fn))
                return false;

        const char *e = endswith(fn, ".public");
        if (!e)
                return false;

        return e != fn;
}

static bool manager_has_public_key(Manager *m, EVP_PKEY *needle) {
        int r;

        assert(m);

        EVP_PKEY *pkey;
        HASHMAP_FOREACH(pkey, m->public_keys) {
                r = sym_EVP_PKEY_eq(pkey, needle);
                if (r > 0)
                        return true;

                /* EVP_PKEY_eq() returns -1 and -2 too under some conditions, which we'll all treat as "not the same" */
        }

        r = sym_EVP_PKEY_eq(m->private_key, needle);
        if (r > 0)
                return true;

        return false;
}

static int method_add_signing_key(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        const char *fn, *pem;
        uint64_t flags;
        r = sd_bus_message_read(message, "sst", &fn, &pem, &flags);
        if (r < 0)
                return r;

        if (flags != 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Flags parameter must be zero.");
        if (!valid_public_key_name(fn))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Public key name not valid: %s", fn);
        if (streq(fn, "local.public"))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Refusing to write local public key.");

        if (hashmap_contains(m->public_keys, fn))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Public key name already exists: %s", fn);

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.manage-signing-keys",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        r = openssl_pubkey_from_pem(pem, /* pem_size= */ SIZE_MAX, &pkey);
        if (r == -EIO)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Public key invalid: %s", fn);
        if (r < 0)
                return r;

        /* Make sure the local key is loaded before can detect conflicts */
        r = manager_acquire_key_pair(m);
        if (r < 0)
                return r;

        if (manager_has_public_key(m, pkey))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Public key already exists: %s", fn);

        _cleanup_free_ char *pem_reformatted = NULL;
        r = openssl_pubkey_to_pem(pkey, &pem_reformatted);
        if (r < 0)
                return log_error_errno(r, "Failed to convert public key to PEM: %m");

        _cleanup_free_ char *fn_copy = strdup(fn);
        if (!fn_copy)
                return log_oom();

        _cleanup_free_ char *p = path_join("/var/lib/systemd/home/", fn);
        if (!p)
                return log_oom();

        r = write_string_file(p, pem_reformatted, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755|WRITE_STRING_FILE_MODE_0444);
        if (r < 0)
                return log_error_errno(r, "Failed to write public key PEM to '%s': %m", p);

        r = hashmap_ensure_put(&m->public_keys, &public_key_hash_ops, fn_copy, pkey);
        if (r < 0) {
                (void) unlink(p);
                return log_error_errno(r, "Failed to add public key to set: %m");
        }

        TAKE_PTR(fn_copy);
        TAKE_PTR(pkey);

        return sd_bus_reply_method_return(message, NULL);
}

static int method_remove_signing_key(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        const char *fn;
        uint64_t flags;
        r = sd_bus_message_read(message, "st", &fn, &flags);
        if (r < 0)
                return r;

        if (flags != 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Flags parameter must be zero.");

        if (!valid_public_key_name(fn))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Public key name not valid: %s", fn);

        if (streq(fn, "local.public"))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Refusing to remove local key.");

        if (!hashmap_contains(m->public_keys, fn))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Public key name does not exist: %s", fn);

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.home1.manage-signing-keys",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* Will call us back */

        _cleanup_free_ char *p = path_join("/var/lib/systemd/home/", fn);
        if (!p)
                return log_oom();

        if (unlink(p) < 0)
                return log_error_errno(errno, "Failed to remove '%s': %m", p);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        _cleanup_free_ char *fn_free = NULL;
        pkey = ASSERT_PTR(hashmap_remove2(m->public_keys, fn, (void**) &fn_free));

        return sd_bus_reply_method_return(message, NULL);
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
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
        SD_BUS_METHOD_WITH_ARGS("ActivateHomeIfReferenced",
                                SD_BUS_ARGS("s", user_name, "s", secret),
                                SD_BUS_NO_RESULT,
                                method_activate_home,
                                SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_SENSITIVE),
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
        SD_BUS_METHOD_WITH_ARGS("AdoptHome",
                                SD_BUS_ARGS("s", image_path, "t", flags),
                                SD_BUS_NO_RESULT,
                                method_adopt_home,
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
        SD_BUS_METHOD_WITH_ARGS("CreateHomeEx",
                                SD_BUS_ARGS("s", user_record, "a{sh}", blobs, "t", flags),
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
        SD_BUS_METHOD_WITH_ARGS("UpdateHomeEx",
                                SD_BUS_ARGS("s", user_record, "a{sh}", blobs, "t", flags),
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
        SD_BUS_METHOD_WITH_ARGS("RefHomeUnrestricted",
                                SD_BUS_ARGS("s", user_name, "b", please_suspend),
                                SD_BUS_RESULT("h", send_fd),
                                method_ref_home,
                                0),
        SD_BUS_METHOD_WITH_ARGS("ReleaseHome",
                                SD_BUS_ARGS("s", user_name),
                                SD_BUS_NO_RESULT,
                                method_release_home,
                                0),

        SD_BUS_METHOD_WITH_ARGS("ListSigningKeys",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("a(sst)", keys),
                                method_list_signing_keys,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("GetSigningKey",
                                SD_BUS_RESULT("s", name),
                                SD_BUS_RESULT("s", der, "t", flags),
                                method_get_signing_key,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("AddSigningKey",
                                SD_BUS_RESULT("s", name, "s", pem, "t", flags),
                                SD_BUS_NO_RESULT,
                                method_add_signing_key,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("RemoveSigningKey",
                                SD_BUS_RESULT("s", name, "t", flags),
                                SD_BUS_NO_RESULT,
                                method_remove_signing_key,
                                SD_BUS_VTABLE_UNPRIVILEGED),

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
