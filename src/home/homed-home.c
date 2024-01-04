/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif

#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/vfs.h>

#include "blockdev-util.h"
#include "btrfs-util.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "data-fd-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "home-util.h"
#include "homed-home-bus.h"
#include "homed-home.h"
#include "memfd-util.h"
#include "missing_magic.h"
#include "missing_mman.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "quota-util.h"
#include "resize-fs.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "uid-alloc-range.h"
#include "user-record-password-quality.h"
#include "user-record-sign.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"

/* Retry to deactivate home directories again and again every 15s until it works */
#define RETRY_DEACTIVATE_USEC (15U * USEC_PER_SEC)

#define HOME_USERS_MAX 500
#define PENDING_OPERATIONS_MAX 100

assert_cc(HOME_UID_MIN <= HOME_UID_MAX);
assert_cc(HOME_USERS_MAX <= (HOME_UID_MAX - HOME_UID_MIN + 1));

static int home_start_work(Home *h, const char *verb, UserRecord *hr, UserRecord *secret);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(operation_hash_ops, void, trivial_hash_func, trivial_compare_func, Operation, operation_unref);

static int suitable_home_record(UserRecord *hr) {
        int r;

        assert(hr);

        if (!hr->user_name)
                return -EUNATCH;

        /* We are a bit more restrictive with what we accept as homed-managed user than what we accept in
         * home records in general. Let's enforce the stricter rule here. */
        if (!suitable_user_name(hr->user_name))
                return -EINVAL;
        if (!uid_is_valid(hr->uid))
                return -EINVAL;

        /* Insist we are outside of the dynamic and system range */
        if (uid_is_system(hr->uid) || gid_is_system(user_record_gid(hr)) ||
            uid_is_dynamic(hr->uid) || gid_is_dynamic(user_record_gid(hr)))
                return -EADDRNOTAVAIL;

        /* Insist that GID and UID match */
        if (user_record_gid(hr) != (gid_t) hr->uid)
                return -EBADSLT;

        /* Similar for the realm */
        if (hr->realm) {
                r = suitable_realm(hr->realm);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        return 0;
}

int home_new(Manager *m, UserRecord *hr, const char *sysfs, Home **ret) {
        _cleanup_(home_freep) Home *home = NULL;
        _cleanup_free_ char *nm = NULL, *ns = NULL;
        int r;

        assert(m);
        assert(hr);

        r = suitable_home_record(hr);
        if (r < 0)
                return r;

        if (hashmap_contains(m->homes_by_name, hr->user_name))
                return -EBUSY;

        if (hashmap_contains(m->homes_by_uid, UID_TO_PTR(hr->uid)))
                return -EBUSY;

        if (sysfs && hashmap_contains(m->homes_by_sysfs, sysfs))
                return -EBUSY;

        if (hashmap_size(m->homes_by_name) >= HOME_USERS_MAX)
                return -EUSERS;

        nm = strdup(hr->user_name);
        if (!nm)
                return -ENOMEM;

        if (sysfs) {
                ns = strdup(sysfs);
                if (!ns)
                        return -ENOMEM;
        }

        home = new(Home, 1);
        if (!home)
                return -ENOMEM;

        *home = (Home) {
                .manager = m,
                .user_name = TAKE_PTR(nm),
                .uid = hr->uid,
                .state = _HOME_STATE_INVALID,
                .worker_stdout_fd = -EBADF,
                .sysfs = TAKE_PTR(ns),
                .signed_locally = -1,
                .pin_fd = -EBADF,
                .luks_lock_fd = -EBADF,
        };

        r = hashmap_put(m->homes_by_name, home->user_name, home);
        if (r < 0)
                return r;

        r = hashmap_put(m->homes_by_uid, UID_TO_PTR(home->uid), home);
        if (r < 0)
                return r;

        if (home->sysfs) {
                r = hashmap_put(m->homes_by_sysfs, home->sysfs, home);
                if (r < 0)
                        return r;
        }

        r = user_record_clone(hr, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &home->record);
        if (r < 0)
                return r;

        (void) bus_manager_emit_auto_login_changed(m);
        (void) bus_home_emit_change(home);
        (void) manager_schedule_rebalance(m, /* immediately= */ false);

        if (ret)
                *ret = TAKE_PTR(home);
        else
                TAKE_PTR(home);

        return 0;
}

Home *home_free(Home *h) {

        if (!h)
                return NULL;

        if (h->manager) {
                (void) bus_home_emit_remove(h);
                (void) bus_manager_emit_auto_login_changed(h->manager);

                if (h->user_name)
                        (void) hashmap_remove_value(h->manager->homes_by_name, h->user_name, h);

                if (uid_is_valid(h->uid))
                        (void) hashmap_remove_value(h->manager->homes_by_uid, UID_TO_PTR(h->uid), h);

                if (h->sysfs)
                        (void) hashmap_remove_value(h->manager->homes_by_sysfs, h->sysfs, h);

                if (h->worker_pid > 0)
                        (void) hashmap_remove_value(h->manager->homes_by_worker_pid, PID_TO_PTR(h->worker_pid), h);

                if (h->manager->gc_focus == h)
                        h->manager->gc_focus = NULL;

                (void) manager_schedule_rebalance(h->manager, /* immediately= */ false);
        }

        user_record_unref(h->record);
        user_record_unref(h->secret);

        h->worker_event_source = sd_event_source_disable_unref(h->worker_event_source);
        safe_close(h->worker_stdout_fd);
        free(h->user_name);
        free(h->sysfs);

        h->ref_event_source_please_suspend = sd_event_source_disable_unref(h->ref_event_source_please_suspend);
        h->ref_event_source_dont_suspend = sd_event_source_disable_unref(h->ref_event_source_dont_suspend);

        h->pending_operations = ordered_set_free(h->pending_operations);
        h->pending_event_source = sd_event_source_disable_unref(h->pending_event_source);
        h->deferred_change_event_source = sd_event_source_disable_unref(h->deferred_change_event_source);

        h->current_operation = operation_unref(h->current_operation);

        safe_close(h->pin_fd);
        safe_close(h->luks_lock_fd);

        h->retry_deactivate_event_source = sd_event_source_disable_unref(h->retry_deactivate_event_source);

        return mfree(h);
}

int home_set_record(Home *h, UserRecord *hr) {
        _cleanup_(user_record_unrefp) UserRecord *new_hr = NULL;
        Home *other;
        int r;

        assert(h);
        assert(h->user_name);
        assert(h->record);
        assert(hr);

        if (user_record_equal(h->record, hr))
                return 0;

        r = suitable_home_record(hr);
        if (r < 0)
                return r;

        if (!user_record_compatible(h->record, hr))
                return -EREMCHG;

        if (!FLAGS_SET(hr->mask, USER_RECORD_REGULAR) ||
            FLAGS_SET(hr->mask, USER_RECORD_SECRET))
                return -EINVAL;

        if (FLAGS_SET(h->record->mask, USER_RECORD_STATUS)) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                /* Hmm, the existing record has status fields? If so, copy them over */

                v = json_variant_ref(hr->json);
                r = json_variant_set_field(&v, "status", json_variant_by_key(h->record->json, "status"));
                if (r < 0)
                        return r;

                new_hr = user_record_new();
                if (!new_hr)
                        return -ENOMEM;

                r = user_record_load(new_hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        return r;

                hr = new_hr;
        }

        other = hashmap_get(h->manager->homes_by_uid, UID_TO_PTR(hr->uid));
        if (other && other != h)
                return -EBUSY;

        if (h->uid != hr->uid) {
                r = hashmap_remove_and_replace(h->manager->homes_by_uid, UID_TO_PTR(h->uid), UID_TO_PTR(hr->uid), h);
                if (r < 0)
                        return r;
        }

        user_record_unref(h->record);
        h->record = user_record_ref(hr);
        h->uid = h->record->uid;

        /* The updated record might have a different autologin setting, trigger a PropertiesChanged event for it */
        (void) bus_manager_emit_auto_login_changed(h->manager);
        (void) bus_home_emit_change(h);

        return 0;
}

int home_save_record(Home *h) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *text = NULL;
        const char *fn;
        int r;

        assert(h);

        v = json_variant_ref(h->record->json);
        r = json_variant_normalize(&v);
        if (r < 0)
                log_warning_errno(r, "User record could not be normalized.");

        r = json_variant_format(v, JSON_FORMAT_PRETTY|JSON_FORMAT_NEWLINE, &text);
        if (r < 0)
                return r;

        (void) mkdir("/var/lib/systemd/", 0755);
        (void) mkdir(home_record_dir(), 0700);

        fn = strjoina(home_record_dir(), "/", h->user_name, ".identity");

        r = write_string_file(fn, text, WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MODE_0600|WRITE_STRING_FILE_SYNC);
        if (r < 0)
                return r;

        return 0;
}

int home_unlink_record(Home *h) {
        const char *fn;

        assert(h);

        fn = strjoina(home_record_dir(), "/", h->user_name, ".identity");
        if (unlink(fn) < 0 && errno != ENOENT)
                return -errno;

        fn = strjoina("/run/systemd/home/", h->user_name, ".ref");
        if (unlink(fn) < 0 && errno != ENOENT)
                return -errno;

        return 0;
}

static void home_unpin(Home *h) {
        assert(h);

        if (h->pin_fd < 0)
                return;

        h->pin_fd = safe_close(h->pin_fd);
        log_debug("Successfully closed pin fd on home for %s.", h->user_name);
}

static void home_pin(Home *h) {
        const char *path;

        assert(h);

        if (h->pin_fd >= 0) /* Already pinned? */
                return;

        path = user_record_home_directory(h->record);
        if (!path) {
                log_warning("No home directory path to pin for %s, ignoring.", h->user_name);
                return;
        }

        h->pin_fd = open(path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (h->pin_fd < 0) {
                log_warning_errno(errno, "Couldn't open home directory '%s' for pinning, ignoring: %m", path);
                return;
        }

        log_debug("Successfully pinned home directory '%s'.", path);
}

static void home_update_pin_fd(Home *h, HomeState state) {
        assert(h);

        if (state < 0)
                state = home_get_state(h);

        return HOME_STATE_SHALL_PIN(state) ? home_pin(h) : home_unpin(h);
}

static void home_maybe_close_luks_lock_fd(Home *h, HomeState state) {
        assert(h);

        if (h->luks_lock_fd < 0)
                return;

        if (state < 0)
                state = home_get_state(h);

        /* Keep the lock as long as the home dir is active or has some operation going */
        if (HOME_STATE_IS_EXECUTING_OPERATION(state) || HOME_STATE_IS_ACTIVE(state) || state == HOME_LOCKED)
                return;

        h->luks_lock_fd = safe_close(h->luks_lock_fd);
        log_debug("Successfully closed LUKS backing file lock for %s.", h->user_name);
}

static void home_maybe_stop_retry_deactivate(Home *h, HomeState state) {
        assert(h);

        /* Free the deactivation retry event source if we won't need it anymore. Specifically, we'll free the
         * event source whenever the home directory is already deactivated (and we thus where successful) or
         * if we start executing an operation that indicates that the home directory is going to be used or
         * operated on again. Also, if the home is referenced again stop the timer */

        if (HOME_STATE_MAY_RETRY_DEACTIVATE(state) &&
            !h->ref_event_source_dont_suspend &&
            !h->ref_event_source_please_suspend)
                return;

        h->retry_deactivate_event_source = sd_event_source_disable_unref(h->retry_deactivate_event_source);
}

static int home_deactivate_internal(Home *h, bool force, sd_bus_error *error);
static void home_start_retry_deactivate(Home *h);

static int home_on_retry_deactivate(sd_event_source *s, uint64_t usec, void *userdata) {
        Home *h = ASSERT_PTR(userdata);
        HomeState state;

        assert(s);

        /* 15s after the last attempt to deactivate the home directory passed. Let's try it one more time. */

        h->retry_deactivate_event_source = sd_event_source_disable_unref(h->retry_deactivate_event_source);

        state = home_get_state(h);
        if (!HOME_STATE_MAY_RETRY_DEACTIVATE(state))
                return 0;

        if (IN_SET(state, HOME_ACTIVE, HOME_LINGERING)) {
                log_info("Again trying to deactivate home directory.");

                /* If we are not executing any operation, let's start deactivating now. Note that this will
                 * restart our timer again, we are gonna be called again if this doesn't work. */
                (void) home_deactivate_internal(h, /* force= */ false, NULL);
        } else
                /* if we are executing an operation (specifically, area already running a deactivation
                 * operation), then simply reque the timer, so that we retry again. */
                home_start_retry_deactivate(h);

        return 0;
}

static void home_start_retry_deactivate(Home *h) {
        int r;

        assert(h);
        assert(h->manager);

        /* Already allocated? */
        if (h->retry_deactivate_event_source)
                return;

        /* If the home directory is being used now don't start the timer */
        if (h->ref_event_source_dont_suspend || h->ref_event_source_please_suspend)
                return;

        r = sd_event_add_time_relative(
                        h->manager->event,
                        &h->retry_deactivate_event_source,
                        CLOCK_MONOTONIC,
                        RETRY_DEACTIVATE_USEC,
                        1*USEC_PER_MINUTE,
                        home_on_retry_deactivate,
                        h);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to install retry-deactivate event source, ignoring: %m");

        (void) sd_event_source_set_description(h->retry_deactivate_event_source, "retry-deactivate");
}

static void home_set_state(Home *h, HomeState state) {
        HomeState old_state, new_state;

        assert(h);

        old_state = home_get_state(h);
        h->state = state;
        new_state = home_get_state(h); /* Query the new state, since the 'state' variable might be set to -1,
                                        * in which case we synthesize an high-level state on demand */

        log_info("%s: changing state %s %s %s", h->user_name,
                 home_state_to_string(old_state),
                 special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                 home_state_to_string(new_state));

        home_update_pin_fd(h, new_state);
        home_maybe_close_luks_lock_fd(h, new_state);
        home_maybe_stop_retry_deactivate(h, new_state);

        if (HOME_STATE_IS_EXECUTING_OPERATION(old_state) && !HOME_STATE_IS_EXECUTING_OPERATION(new_state)) {
                /* If we just finished executing some operation, process the queue of pending operations. And
                 * enqueue it for GC too. */

                home_schedule_operation(h, NULL, NULL);
                manager_reschedule_rebalance(h->manager);
                manager_enqueue_gc(h->manager, h);
        }
}

static int home_parse_worker_stdout(int _fd, UserRecord **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_close_ int fd = _fd; /* take possession, even on failure */
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        unsigned line, column;
        struct stat st;
        int r;

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat stdout fd: %m");

        assert(S_ISREG(st.st_mode));

        if (st.st_size == 0) { /* empty record */
                *ret = NULL;
                return 0;
        }

        if (lseek(fd, SEEK_SET, 0) < 0)
                return log_error_errno(errno, "Failed to seek to beginning of memfd: %m");

        f = take_fdopen(&fd, "r");
        if (!f)
                return log_error_errno(errno, "Failed to reopen memfd: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *text = NULL;

                r = read_full_stream(f, &text, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read from client: %m");

                log_debug("Got from worker: %s", text);
                rewind(f);
        }

        r = json_parse_file(f, "stdout", JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return log_error_errno(r, "Failed to parse identity at %u:%u: %m", line, column);

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return log_error_errno(r, "Failed to load home record identity: %m");

        *ret = TAKE_PTR(hr);
        return 1;
}

static int home_verify_user_record(Home *h, UserRecord *hr, bool *ret_signed_locally, sd_bus_error *ret_error) {
        int is_signed;

        assert(h);
        assert(hr);
        assert(ret_signed_locally);

        is_signed = manager_verify_user_record(h->manager, hr);
        switch (is_signed) {

        case USER_RECORD_SIGNED_EXCLUSIVE:
                log_info("Home %s is signed exclusively by our key, accepting.", hr->user_name);
                *ret_signed_locally = true;
                return 0;

        case USER_RECORD_SIGNED:
                log_info("Home %s is signed by our key (and others), accepting.", hr->user_name);
                *ret_signed_locally = false;
                return 0;

        case USER_RECORD_FOREIGN:
                log_info("Home %s is signed by foreign key we like, accepting.", hr->user_name);
                *ret_signed_locally = false;
                return 0;

        case USER_RECORD_UNSIGNED:
                sd_bus_error_setf(ret_error, BUS_ERROR_BAD_SIGNATURE, "User record %s is not signed at all, refusing.", hr->user_name);
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Home %s contains user record that is not signed at all, refusing.", hr->user_name);

        case -ENOKEY:
                sd_bus_error_setf(ret_error, BUS_ERROR_BAD_SIGNATURE, "User record %s is not signed by any known key, refusing.", hr->user_name);
                return log_error_errno(is_signed, "Home %s contains user record that is not signed by any known key, refusing.", hr->user_name);

        default:
                assert(is_signed < 0);
                return log_error_errno(is_signed, "Failed to verify signature on user record for %s, refusing fixation: %m", hr->user_name);
        }
}

static int convert_worker_errno(Home *h, int e, sd_bus_error *error) {
        /* Converts the error numbers the worker process returned into somewhat sensible dbus errors */

        switch (e) {

        case -EMSGSIZE:
                return sd_bus_error_set(error, BUS_ERROR_BAD_HOME_SIZE, "File systems of this type cannot be shrunk");
        case -ETXTBSY:
                return sd_bus_error_set(error, BUS_ERROR_BAD_HOME_SIZE, "File systems of this type can only be shrunk offline");
        case -ERANGE:
                return sd_bus_error_set(error, BUS_ERROR_BAD_HOME_SIZE, "File system size too small");
        case -ENOLINK:
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "System does not support selected storage backend");
        case -EPROTONOSUPPORT:
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "System does not support selected file system");
        case -ENOTTY:
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Operation not supported on storage backend");
        case -ESOCKTNOSUPPORT:
                return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Operation not supported on file system");
        case -ENOKEY:
                return sd_bus_error_setf(error, BUS_ERROR_BAD_PASSWORD, "Password for home %s is incorrect or not sufficient for authentication.", h->user_name);
        case -EBADSLT:
                return sd_bus_error_setf(error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN, "Password for home %s is incorrect or not sufficient, and configured security token not found either.", h->user_name);
        case -EREMOTEIO:
                return sd_bus_error_setf(error, BUS_ERROR_BAD_RECOVERY_KEY, "Recovery key for home %s is incorrect or not sufficient for authentication.", h->user_name);
        case -ENOANO:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_PIN_NEEDED, "PIN for security token required.");
        case -ERFKILL:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_PROTECTED_AUTHENTICATION_PATH_NEEDED, "Security token requires protected authentication path.");
        case -EMEDIUMTYPE:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_USER_PRESENCE_NEEDED, "Security token requires presence confirmation.");
        case -ENOCSI:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_USER_VERIFICATION_NEEDED, "Security token requires user verification.");
        case -ENOSTR:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_ACTION_TIMEOUT, "Token action timeout. (User was supposed to verify presence or similar, by interacting with the token, and didn't do that in time.)");
        case -EOWNERDEAD:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_PIN_LOCKED, "PIN of security token locked.");
        case -ENOLCK:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_BAD_PIN, "Bad PIN of security token.");
        case -ETOOMANYREFS:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_BAD_PIN_FEW_TRIES_LEFT, "Bad PIN of security token, and only a few tries left.");
        case -EUCLEAN:
                return sd_bus_error_set(error, BUS_ERROR_TOKEN_BAD_PIN_ONE_TRY_LEFT, "Bad PIN of security token, and only one try left.");
        case -EBUSY:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "Home %s is currently being used, or an operation on home %s is currently being executed.", h->user_name, h->user_name);
        case -ENOEXEC:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_NOT_ACTIVE, "Home %s is currently not active", h->user_name);
        case -ENOSPC:
                return sd_bus_error_setf(error, BUS_ERROR_NO_DISK_SPACE, "Not enough disk space for home %s", h->user_name);
        case -EKEYREVOKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_CANT_AUTHENTICATE, "Home %s has no password or other authentication mechanism defined.", h->user_name);
        case -EADDRINUSE:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_IN_USE, "Home %s is currently being used elsewhere.", h->user_name);
        }

        return 0;
}

static void home_count_bad_authentication(Home *h, int error, bool save) {
        int r;

        assert(h);

        if (!IN_SET(error,
                    -ENOKEY,       /* Password incorrect */
                    -EBADSLT,      /* Password incorrect and no token */
                    -EREMOTEIO))   /* Recovery key incorrect */
                return;

        r = user_record_bad_authentication(h->record);
        if (r < 0) {
                log_warning_errno(r, "Failed to increase bad authentication counter, ignoring: %m");
                return;
        }

        if (save) {
                r = home_save_record(h);
                if (r < 0)
                        log_warning_errno(r, "Failed to write home record to disk, ignoring: %m");
        }
}

static void home_fixate_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        bool signed_locally;
        int r;

        assert(h);
        assert(IN_SET(h->state, HOME_FIXATING, HOME_FIXATING_FOR_ACTIVATION, HOME_FIXATING_FOR_ACQUIRE));

        secret = TAKE_PTR(h->secret); /* Take possession */

        if (ret < 0) {
                (void) home_count_bad_authentication(h, ret, /* save= */ false);

                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Fixation failed: %m");
                goto fail;
        }
        if (!hr) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Did not receive user record from worker process, fixation failed.");
                goto fail;
        }

        r = home_verify_user_record(h, hr, &signed_locally, &error);
        if (r < 0)
                goto fail;

        r = home_set_record(h, hr);
        if (r < 0) {
                log_error_errno(r, "Failed to update home record: %m");
                goto fail;
        }

        h->signed_locally = signed_locally;

        /* When we finished fixating (and don't follow-up with activation), let's count this as good authentication */
        if (h->state == HOME_FIXATING) {
                r = user_record_good_authentication(h->record);
                if (r < 0)
                        log_warning_errno(r, "Failed to increase good authentication counter, ignoring: %m");
        }

        r = home_save_record(h);
        if (r < 0)
                log_warning_errno(r, "Failed to write home record to disk, ignoring: %m");

        if (IN_SET(h->state, HOME_FIXATING_FOR_ACTIVATION, HOME_FIXATING_FOR_ACQUIRE)) {

                r = home_start_work(h, "activate", h->record, secret);
                if (r < 0) {
                        h->current_operation = operation_result_unref(h->current_operation, r, NULL);
                        home_set_state(h, _HOME_STATE_INVALID);
                } else
                        home_set_state(h, h->state == HOME_FIXATING_FOR_ACTIVATION ? HOME_ACTIVATING : HOME_ACTIVATING_FOR_ACQUIRE);

                return;
        }

        log_debug("Fixation of %s completed.", h->user_name);

        h->current_operation = operation_result_unref(h->current_operation, 0, NULL);

        /* Reset the state to "invalid", which makes home_get_state() test if the image exists and returns
         * HOME_ABSENT vs. HOME_INACTIVE as necessary. */
        home_set_state(h, _HOME_STATE_INVALID);
        (void) manager_schedule_rebalance(h->manager, /* immediately= */ false);
        return;

fail:
        /* If fixation fails, we stay in unfixated state! */
        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, HOME_UNFIXATED);
}

static void home_activate_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(IN_SET(h->state, HOME_ACTIVATING, HOME_ACTIVATING_FOR_ACQUIRE));

        if (ret < 0) {
                (void) home_count_bad_authentication(h, ret, /* save= */ true);

                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Activation failed: %m");
                goto finish;
        }

        if (hr) {
                bool signed_locally;

                r = home_verify_user_record(h, hr, &signed_locally, &error);
                if (r < 0)
                        goto finish;

                r = home_set_record(h, hr);
                if (r < 0) {
                        log_error_errno(r, "Failed to update home record, ignoring: %m");
                        goto finish;
                }

                h->signed_locally = signed_locally;

                r = user_record_good_authentication(h->record);
                if (r < 0)
                        log_warning_errno(r, "Failed to increase good authentication counter, ignoring: %m");

                r = home_save_record(h);
                if (r < 0)
                        log_warning_errno(r, "Failed to write home record to disk, ignoring: %m");
        }

        log_debug("Activation of %s completed.", h->user_name);
        r = 0;

finish:
        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, _HOME_STATE_INVALID);

        if (r >= 0)
                (void) manager_schedule_rebalance(h->manager, /* immediately= */ true);
}

static void home_deactivate_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(h->state == HOME_DEACTIVATING);
        assert(!hr); /* We don't expect a record on this operation */

        if (ret < 0) {
                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Deactivation of %s failed: %m", h->user_name);
                goto finish;
        }

        log_debug("Deactivation of %s completed.", h->user_name);
        r = 0;

finish:
        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, _HOME_STATE_INVALID);

        if (r >= 0)
                (void) manager_schedule_rebalance(h->manager, /* immediately= */ true);
}

static void home_remove_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Manager *m;
        int r;

        assert(h);
        assert(h->state == HOME_REMOVING);
        assert(!hr); /* We don't expect a record on this operation */

        m = h->manager;

        if (ret < 0 && ret != -EALREADY) {
                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Removing %s failed: %m", h->user_name);
                goto fail;
        }

        /* For a couple of storage types we can't delete the actual data storage when called (such as LUKS on
         * partitions like USB sticks, or so). Sometimes these storage locations are among those we normally
         * automatically discover in /home or in udev. When such a home is deleted let's hence issue a rescan
         * after completion, so that "unfixated" entries are rediscovered.  */
        if (!IN_SET(user_record_test_image_path(h->record), USER_TEST_UNDEFINED, USER_TEST_ABSENT))
                manager_enqueue_rescan(m);

        /* The image is now removed from disk. Now also remove our stored record */
        r = home_unlink_record(h);
        if (r < 0) {
                log_error_errno(r, "Removing record file failed: %m");
                goto fail;
        }

        log_debug("Removal of %s completed.", h->user_name);
        h->current_operation = operation_result_unref(h->current_operation, 0, NULL);

        /* Unload this record from memory too now. */
        h = home_free(h);

        (void) manager_schedule_rebalance(m, /* immediately= */ true);
        return;

fail:
        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, _HOME_STATE_INVALID);
}

static void home_create_finish(Home *h, int ret, UserRecord *hr) {
        int r;

        assert(h);
        assert(h->state == HOME_CREATING);

        if (ret < 0) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                (void) convert_worker_errno(h, ret, &error);
                log_error_errno(ret, "Operation on %s failed: %m", h->user_name);
                h->current_operation = operation_result_unref(h->current_operation, ret, &error);

                if (h->unregister_on_failure) {
                        (void) home_unlink_record(h);
                        h = home_free(h);
                        return;
                }

                home_set_state(h, _HOME_STATE_INVALID);
                return;
        }

        if (hr) {
                r = home_set_record(h, hr);
                if (r < 0)
                        log_warning_errno(r, "Failed to update home record, ignoring: %m");
        }

        r = home_save_record(h);
        if (r < 0)
                log_warning_errno(r, "Failed to save record to disk, ignoring: %m");

        log_debug("Creation of %s completed.", h->user_name);

        h->current_operation = operation_result_unref(h->current_operation, 0, NULL);
        home_set_state(h, _HOME_STATE_INVALID);

        (void) manager_schedule_rebalance(h->manager, /* immediately= */ true);
}

static void home_change_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);

        if (ret < 0) {
                (void) home_count_bad_authentication(h, ret, /* save= */ true);

                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Change operation failed: %m");
                goto finish;
        }

        if (hr) {
                r = home_set_record(h, hr);
                if (r < 0)
                        log_warning_errno(r, "Failed to update home record, ignoring: %m");
                else {
                        r = user_record_good_authentication(h->record);
                        if (r < 0)
                                log_warning_errno(r, "Failed to increase good authentication counter, ignoring: %m");

                        r = home_save_record(h);
                        if (r < 0)
                                log_warning_errno(r, "Failed to write home record to disk, ignoring: %m");
                }
        }

        log_debug("Change operation of %s completed.", h->user_name);
        (void) manager_schedule_rebalance(h->manager, /* immediately= */ false);
        r = 0;

finish:
        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, _HOME_STATE_INVALID);
}

static void home_locking_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(h->state == HOME_LOCKING);

        if (ret < 0) {
                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Locking operation failed: %m");
                goto finish;
        }

        log_debug("Locking operation of %s completed.", h->user_name);
        h->current_operation = operation_result_unref(h->current_operation, 0, NULL);
        home_set_state(h, HOME_LOCKED);
        return;

finish:
        /* If a specific home doesn't know the concept of locking, then that's totally OK, don't propagate
         * the error if we are executing a LockAllHomes() operation. */

        if (h->current_operation->type == OPERATION_LOCK_ALL && r == -ENOTTY)
                h->current_operation = operation_result_unref(h->current_operation, 0, NULL);
        else
                h->current_operation = operation_result_unref(h->current_operation, r, &error);

        home_set_state(h, _HOME_STATE_INVALID);
}

static void home_unlocking_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(IN_SET(h->state, HOME_UNLOCKING, HOME_UNLOCKING_FOR_ACQUIRE));

        if (ret < 0) {
                (void) home_count_bad_authentication(h, ret, /* save= */ true);

                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Unlocking operation failed: %m");

                /* Revert to locked state */
                home_set_state(h, HOME_LOCKED);
                h->current_operation = operation_result_unref(h->current_operation, r, &error);
                return;
        }

        r = user_record_good_authentication(h->record);
        if (r < 0)
                log_warning_errno(r, "Failed to increase good authentication counter, ignoring: %m");
        else {
                r = home_save_record(h);
                if (r < 0)
                        log_warning_errno(r, "Failed to write home record to disk, ignoring: %m");
        }

        log_debug("Unlocking operation of %s completed.", h->user_name);

        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, _HOME_STATE_INVALID);
        return;
}

static void home_authenticating_finish(Home *h, int ret, UserRecord *hr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(IN_SET(h->state, HOME_AUTHENTICATING, HOME_AUTHENTICATING_WHILE_ACTIVE, HOME_AUTHENTICATING_FOR_ACQUIRE));

        if (ret < 0) {
                (void) home_count_bad_authentication(h, ret, /* save= */ true);

                (void) convert_worker_errno(h, ret, &error);
                r = log_error_errno(ret, "Authentication failed: %m");
                goto finish;
        }

        if (hr) {
                r = home_set_record(h, hr);
                if (r < 0)
                        log_warning_errno(r, "Failed to update home record, ignoring: %m");
                else {
                        r = user_record_good_authentication(h->record);
                        if (r < 0)
                                log_warning_errno(r, "Failed to increase good authentication counter, ignoring: %m");

                        r = home_save_record(h);
                        if (r < 0)
                                log_warning_errno(r, "Failed to write home record to disk, ignoring: %m");
                }
        }

        log_debug("Authentication of %s completed.", h->user_name);
        r = 0;

finish:
        h->current_operation = operation_result_unref(h->current_operation, r, &error);
        home_set_state(h, _HOME_STATE_INVALID);
}

static int home_on_worker_process(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        Home *h = ASSERT_PTR(userdata);
        int ret;

        assert(s);
        assert(si);

        assert(h->worker_pid == si->si_pid);
        assert(h->worker_event_source);
        assert(h->worker_stdout_fd >= 0);

        (void) hashmap_remove_value(h->manager->homes_by_worker_pid, PID_TO_PTR(h->worker_pid), h);

        h->worker_pid = 0;
        h->worker_event_source = sd_event_source_disable_unref(h->worker_event_source);

        if (si->si_code != CLD_EXITED) {
                assert(IN_SET(si->si_code, CLD_KILLED, CLD_DUMPED));
                ret = log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Worker process died abnormally with signal %s.", signal_to_string(si->si_status));
        } else if (si->si_status != EXIT_SUCCESS) {
                /* If we received an error code via sd_notify(), use it */
                if (h->worker_error_code != 0)
                        ret = log_debug_errno(h->worker_error_code, "Worker reported error code %s.", errno_to_name(h->worker_error_code));
                else
                        ret = log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Worker exited with exit code %i.", si->si_status);
        } else
                ret = home_parse_worker_stdout(TAKE_FD(h->worker_stdout_fd), &hr);

        h->worker_stdout_fd = safe_close(h->worker_stdout_fd);

        switch (h->state) {

        case HOME_FIXATING:
        case HOME_FIXATING_FOR_ACTIVATION:
        case HOME_FIXATING_FOR_ACQUIRE:
                home_fixate_finish(h, ret, hr);
                break;

        case HOME_ACTIVATING:
        case HOME_ACTIVATING_FOR_ACQUIRE:
                home_activate_finish(h, ret, hr);
                break;

        case HOME_DEACTIVATING:
                home_deactivate_finish(h, ret, hr);
                break;

        case HOME_LOCKING:
                home_locking_finish(h, ret, hr);
                break;

        case HOME_UNLOCKING:
        case HOME_UNLOCKING_FOR_ACQUIRE:
                home_unlocking_finish(h, ret, hr);
                break;

        case HOME_CREATING:
                home_create_finish(h, ret, hr);
                break;

        case HOME_REMOVING:
                home_remove_finish(h, ret, hr);
                break;

        case HOME_UPDATING:
        case HOME_UPDATING_WHILE_ACTIVE:
        case HOME_RESIZING:
        case HOME_RESIZING_WHILE_ACTIVE:
        case HOME_PASSWD:
        case HOME_PASSWD_WHILE_ACTIVE:
                home_change_finish(h, ret, hr);
                break;

        case HOME_AUTHENTICATING:
        case HOME_AUTHENTICATING_WHILE_ACTIVE:
        case HOME_AUTHENTICATING_FOR_ACQUIRE:
                home_authenticating_finish(h, ret, hr);
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int home_start_work(Home *h, const char *verb, UserRecord *hr, UserRecord *secret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(erase_and_freep) char *formatted = NULL;
        _cleanup_close_ int stdin_fd = -EBADF, stdout_fd = -EBADF;
        pid_t pid = 0;
        int r;

        assert(h);
        assert(verb);
        assert(hr);

        if (h->worker_pid != 0)
                return -EBUSY;

        assert(h->worker_stdout_fd < 0);
        assert(!h->worker_event_source);

        v = json_variant_ref(hr->json);

        if (secret) {
                JsonVariant *sub = NULL;

                sub = json_variant_by_key(secret->json, "secret");
                if (!sub)
                        return -ENOKEY;

                r = json_variant_set_field(&v, "secret", sub);
                if (r < 0)
                        return r;
        }

        r = json_variant_format(v, 0, &formatted);
        if (r < 0)
                return r;

        stdin_fd = acquire_data_fd(formatted, strlen(formatted), 0);
        if (stdin_fd < 0)
                return stdin_fd;

        log_debug("Sending to worker: %s", formatted);

        stdout_fd = memfd_create_wrapper("homework-stdout", MFD_CLOEXEC | MFD_NOEXEC_SEAL);
        if (stdout_fd < 0)
                return stdout_fd;

        r = safe_fork_full("(sd-homework)",
                           (int[]) { stdin_fd, stdout_fd, STDERR_FILENO },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                _cleanup_free_ char *joined = NULL;
                const char *homework, *suffix, *unix_path;

                /* Child */

                suffix = getenv("SYSTEMD_HOME_DEBUG_SUFFIX");
                if (suffix) {
                        joined = strjoin("/run/systemd/home/notify.", suffix);
                        if (!joined)
                                return log_oom();
                        unix_path = joined;
                } else
                        unix_path = "/run/systemd/home/notify";

                if (setenv("NOTIFY_SOCKET", unix_path, 1) < 0) {
                        log_error_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_FAILURE);
                }

                /* If we haven't locked the device yet, ask for a lock to be taken and be passed back to us via sd_notify(). */
                if (setenv("SYSTEMD_LUKS_LOCK", one_zero(h->luks_lock_fd < 0), 1) < 0) {
                        log_error_errno(errno, "Failed to set $SYSTEMD_LUKS_LOCK: %m");
                        _exit(EXIT_FAILURE);
                }

                if (h->manager->default_storage >= 0)
                        if (setenv("SYSTEMD_HOME_DEFAULT_STORAGE", user_storage_to_string(h->manager->default_storage), 1) < 0) {
                                log_error_errno(errno, "Failed to set $SYSTEMD_HOME_DEFAULT_STORAGE: %m");
                                _exit(EXIT_FAILURE);
                        }

                if (h->manager->default_file_system_type)
                        if (setenv("SYSTEMD_HOME_DEFAULT_FILE_SYSTEM_TYPE", h->manager->default_file_system_type, 1) < 0) {
                                log_error_errno(errno, "Failed to set $SYSTEMD_HOME_DEFAULT_FILE_SYSTEM_TYPE: %m");
                                _exit(EXIT_FAILURE);
                        }

                r = setenv_systemd_exec_pid(true);
                if (r < 0)
                        log_warning_errno(r, "Failed to update $SYSTEMD_EXEC_PID, ignoring: %m");

                /* Allow overriding the homework path via an environment variable, to make debugging
                 * easier. */
                homework = getenv("SYSTEMD_HOMEWORK_PATH") ?: SYSTEMD_HOMEWORK_PATH;

                execl(homework, homework, verb, NULL);
                log_error_errno(errno, "Failed to invoke %s: %m", homework);
                _exit(EXIT_FAILURE);
        }

        r = sd_event_add_child(h->manager->event, &h->worker_event_source, pid, WEXITED, home_on_worker_process, h);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(h->worker_event_source, "worker");

        r = hashmap_put(h->manager->homes_by_worker_pid, PID_TO_PTR(pid), h);
        if (r < 0) {
                h->worker_event_source = sd_event_source_disable_unref(h->worker_event_source);
                return r;
        }

        h->worker_stdout_fd = TAKE_FD(stdout_fd);
        h->worker_pid = pid;
        h->worker_error_code = 0;

        return 0;
}

static int home_ratelimit(Home *h, sd_bus_error *error) {
        int r, ret;

        assert(h);

        ret = user_record_ratelimit(h->record);
        if (ret < 0)
                return ret;

        if (h->state != HOME_UNFIXATED) {
                r = home_save_record(h);
                if (r < 0)
                        log_warning_errno(r, "Failed to save updated record, ignoring: %m");
        }

        if (ret == 0) {
                usec_t t, n;

                n = now(CLOCK_REALTIME);
                t = user_record_ratelimit_next_try(h->record);

                if (t != USEC_INFINITY && t > n)
                        return sd_bus_error_setf(error, BUS_ERROR_AUTHENTICATION_LIMIT_HIT,
                                                 "Too many login attempts, please try again in %s!",
                                                 FORMAT_TIMESPAN(t - n, USEC_PER_SEC));

                return sd_bus_error_set(error, BUS_ERROR_AUTHENTICATION_LIMIT_HIT, "Too many login attempts, please try again later.");
        }

        return 0;
}

static int home_fixate_internal(
                Home *h,
                UserRecord *secret,
                HomeState for_state,
                sd_bus_error *error) {

        int r;

        assert(h);
        assert(IN_SET(for_state, HOME_FIXATING, HOME_FIXATING_FOR_ACTIVATION, HOME_FIXATING_FOR_ACQUIRE));

        r = home_start_work(h, "inspect", h->record, secret);
        if (r < 0)
                return r;

        if (IN_SET(for_state, HOME_FIXATING_FOR_ACTIVATION, HOME_FIXATING_FOR_ACQUIRE)) {
                /* Remember the secret data, since we need it for the activation again, later on. */
                user_record_unref(h->secret);
                h->secret = user_record_ref(secret);
        }

        home_set_state(h, for_state);
        return 0;
}

int home_fixate(Home *h, UserRecord *secret, sd_bus_error *error) {
        int r;

        assert(h);

        switch (home_get_state(h)) {
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_INACTIVE:
        case HOME_DIRTY:
        case HOME_ACTIVE:
        case HOME_LINGERING:
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ALREADY_FIXATED, "Home %s is already fixated.", h->user_name);
        case HOME_UNFIXATED:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        return home_fixate_internal(h, secret, HOME_FIXATING, error);
}

static int home_activate_internal(Home *h, UserRecord *secret, HomeState for_state, sd_bus_error *error) {
        int r;

        assert(h);
        assert(IN_SET(for_state, HOME_ACTIVATING, HOME_ACTIVATING_FOR_ACQUIRE));

        r = home_start_work(h, "activate", h->record, secret);
        if (r < 0)
                return r;

        home_set_state(h, for_state);
        return 0;
}

int home_activate(Home *h, UserRecord *secret, sd_bus_error *error) {
        int r;

        assert(h);

        switch (home_get_state(h)) {
        case HOME_UNFIXATED:
                return home_fixate_internal(h, secret, HOME_FIXATING_FOR_ACTIVATION, error);
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_ACTIVE:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ALREADY_ACTIVE, "Home %s is already active.", h->user_name);
        case HOME_LINGERING:
                /* If we are lingering, i.e. active but are supposed to be deactivated, then cancel this
                 * timer if the user explicitly asks us to be active */
                h->retry_deactivate_event_source = sd_event_source_disable_unref(h->retry_deactivate_event_source);
                return 0;
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_INACTIVE:
        case HOME_DIRTY:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        return home_activate_internal(h, secret, HOME_ACTIVATING, error);
}

static int home_authenticate_internal(Home *h, UserRecord *secret, HomeState for_state, sd_bus_error *error) {
        int r;

        assert(h);
        assert(IN_SET(for_state, HOME_AUTHENTICATING, HOME_AUTHENTICATING_WHILE_ACTIVE, HOME_AUTHENTICATING_FOR_ACQUIRE));

        r = home_start_work(h, "inspect", h->record, secret);
        if (r < 0)
                return r;

        home_set_state(h, for_state);
        return 0;
}

int home_authenticate(Home *h, UserRecord *secret, sd_bus_error *error) {
        HomeState state;
        int r;

        assert(h);

        state = home_get_state(h);
        switch (state) {
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_UNFIXATED:
        case HOME_INACTIVE:
        case HOME_DIRTY:
        case HOME_ACTIVE:
        case HOME_LINGERING:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        return home_authenticate_internal(h, secret, HOME_STATE_IS_ACTIVE(state) ? HOME_AUTHENTICATING_WHILE_ACTIVE : HOME_AUTHENTICATING, error);
}

static int home_deactivate_internal(Home *h, bool force, sd_bus_error *error) {
        int r;

        assert(h);

        home_unpin(h); /* unpin so that we can deactivate */

        r = home_start_work(h, force ? "deactivate-force" : "deactivate", h->record, NULL);
        if (r < 0)
                /* Operation failed before it even started, reacquire pin fd, if state still dictates so */
                home_update_pin_fd(h, _HOME_STATE_INVALID);
        else {
                home_set_state(h, HOME_DEACTIVATING);
                r = 0;
        }

        /* Let's start a timer to retry deactivation in 15. We'll stop the timer once we manage to deactivate
         * the home directory again, or we start any other operation. */
        home_start_retry_deactivate(h);

        return r;
}

int home_deactivate(Home *h, bool force, sd_bus_error *error) {
        assert(h);

        switch (home_get_state(h)) {
        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_NOT_ACTIVE, "Home %s not active.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_ACTIVE:
        case HOME_LINGERING:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        return home_deactivate_internal(h, force, error);
}

int home_create(Home *h, UserRecord *secret, sd_bus_error *error) {
        int r;

        assert(h);

        switch (home_get_state(h)) {
        case HOME_INACTIVE: {
                int t;

                if (h->record->storage < 0)
                        break; /* if no storage is defined we don't know what precisely to look for, hence
                                * HOME_INACTIVE is OK in that case too. */

                t = user_record_test_image_path(h->record);
                if (IN_SET(t, USER_TEST_MAYBE, USER_TEST_UNDEFINED))
                        break; /* And if the image path test isn't conclusive, let's also go on */

                if (IN_SET(t, -EBADF, -ENOTDIR))
                        return sd_bus_error_setf(error, BUS_ERROR_HOME_EXISTS, "Selected home image of user %s already exists or has wrong inode type.", h->user_name);

                return sd_bus_error_setf(error, BUS_ERROR_HOME_EXISTS, "Selected home image of user %s already exists.", h->user_name);
        }
        case HOME_UNFIXATED:
        case HOME_DIRTY:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_EXISTS, "Home of user %s already exists.", h->user_name);
        case HOME_ABSENT:
                break;
        case HOME_ACTIVE:
        case HOME_LINGERING:
        case HOME_LOCKED:
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "Home %s is currently being used, or an operation on home %s is currently being executed.", h->user_name, h->user_name);
        }

        if (h->record->enforce_password_policy == false)
                log_debug("Password quality check turned off for account, skipping.");
        else {
                r = user_record_check_password_quality(h->record, secret, error);
                if (r < 0)
                        return r;
        }

        r = home_start_work(h, "create", h->record, secret);
        if (r < 0)
                return r;

        home_set_state(h, HOME_CREATING);
        return 0;
}

int home_remove(Home *h, sd_bus_error *error) {
        HomeState state;
        int r;

        assert(h);

        state = home_get_state(h);
        switch (state) {
        case HOME_ABSENT: /* If the home directory is absent, then this is just like unregistering */
                return home_unregister(h, error);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_UNFIXATED:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                break;
        case HOME_ACTIVE:
        case HOME_LINGERING:
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "Home %s is currently being used, or an operation on home %s is currently being executed.", h->user_name, h->user_name);
        }

        r = home_start_work(h, "remove", h->record, NULL);
        if (r < 0)
                return r;

        home_set_state(h, HOME_REMOVING);
        return 0;
}

static int user_record_extend_with_binding(UserRecord *hr, UserRecord *with_binding, UserRecordLoadFlags flags, UserRecord **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *nr = NULL;
        JsonVariant *binding;
        int r;

        assert(hr);
        assert(with_binding);
        assert(ret);

        assert_se(v = json_variant_ref(hr->json));

        binding = json_variant_by_key(with_binding->json, "binding");
        if (binding) {
                r = json_variant_set_field(&v, "binding", binding);
                if (r < 0)
                        return r;
        }

        nr = user_record_new();
        if (!nr)
                return -ENOMEM;

        r = user_record_load(nr, v, flags);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(nr);
        return 0;
}

static int home_update_internal(
                Home *h,
                const char *verb,
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *new_hr = NULL, *saved_secret = NULL, *signed_hr = NULL;
        int r, c;

        assert(h);
        assert(verb);
        assert(hr);

        if (!user_record_compatible(hr, h->record))
                return sd_bus_error_set(error, BUS_ERROR_HOME_RECORD_MISMATCH, "Updated user record is not compatible with existing one.");
        c = user_record_compare_last_change(hr, h->record); /* refuse downgrades */
        if (c < 0)
                return sd_bus_error_set(error, BUS_ERROR_HOME_RECORD_DOWNGRADE, "Refusing to update to older home record.");

        if (!secret && FLAGS_SET(hr->mask, USER_RECORD_SECRET)) {
                r = user_record_clone(hr, USER_RECORD_EXTRACT_SECRET|USER_RECORD_PERMISSIVE, &saved_secret);
                if (r < 0)
                        return r;

                secret = saved_secret;
        }

        r = manager_verify_user_record(h->manager, hr);
        switch (r) {

        case USER_RECORD_UNSIGNED:
                if (h->signed_locally <= 0) /* If the existing record is not owned by us, don't accept an
                                             * unsigned new record. i.e. only implicitly sign new records
                                             * that where previously signed by us too. */
                        return sd_bus_error_setf(error, BUS_ERROR_HOME_RECORD_SIGNED, "Home %s is signed and cannot be modified locally.", h->user_name);

                /* The updated record is not signed, then do so now */
                r = manager_sign_user_record(h->manager, hr, &signed_hr, error);
                if (r < 0)
                        return r;

                hr = signed_hr;
                break;

        case USER_RECORD_SIGNED_EXCLUSIVE:
        case USER_RECORD_SIGNED:
        case USER_RECORD_FOREIGN:
                /* Has already been signed. Great! */
                break;

        case -ENOKEY:
        default:
                return r;
        }

        r = user_record_extend_with_binding(hr, h->record, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &new_hr);
        if (r < 0)
                return r;

        if (c == 0) {
                /* different payload but same lastChangeUSec field? That's not cool! */

                r = user_record_masked_equal(new_hr, h->record, USER_RECORD_REGULAR|USER_RECORD_PRIVILEGED|USER_RECORD_PER_MACHINE);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_bus_error_set(error, BUS_ERROR_HOME_RECORD_MISMATCH, "Home record different but timestamp remained the same, refusing.");
        }

        r = home_start_work(h, verb, new_hr, secret);
        if (r < 0)
                return r;

        return 0;
}

int home_update(Home *h, UserRecord *hr, sd_bus_error *error) {
        HomeState state;
        int r;

        assert(h);
        assert(hr);

        state = home_get_state(h);
        switch (state) {
        case HOME_UNFIXATED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_UNFIXATED, "Home %s has not been fixated yet.", h->user_name);
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_INACTIVE:
        case HOME_DIRTY:
        case HOME_ACTIVE:
        case HOME_LINGERING:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        r = home_update_internal(h, "update", hr, NULL, error);
        if (r < 0)
                return r;

        home_set_state(h, HOME_STATE_IS_ACTIVE(state) ? HOME_UPDATING_WHILE_ACTIVE : HOME_UPDATING);
        return 0;
}

int home_resize(Home *h,
                uint64_t disk_size,
                UserRecord *secret,
                bool automatic,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *c = NULL;
        HomeState state;
        int r;

        assert(h);

        state = home_get_state(h);
        switch (state) {
        case HOME_UNFIXATED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_UNFIXATED, "Home %s has not been fixated yet.", h->user_name);
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_INACTIVE:
        case HOME_DIRTY:
        case HOME_ACTIVE:
        case HOME_LINGERING:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        /* If the user didn't specify any size explicitly and rebalancing is on, then the disk size is
         * determined by automatic rebalancing and hence not user configured but determined by us and thus
         * applied anyway. */
        if (disk_size == UINT64_MAX && h->record->rebalance_weight != REBALANCE_WEIGHT_OFF)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Disk size is being determined by automatic disk space rebalancing.");

        if (disk_size == UINT64_MAX || disk_size == h->record->disk_size) {
                if (h->record->disk_size == UINT64_MAX)
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "No disk size to resize to specified.");

                c = user_record_ref(h->record); /* Shortcut if size is unspecified or matches the record */
        } else {
                _cleanup_(user_record_unrefp) UserRecord *signed_c = NULL;

                if (h->signed_locally <= 0) /* Don't allow changing of records not signed only by us */
                        return sd_bus_error_setf(error, BUS_ERROR_HOME_RECORD_SIGNED, "Home %s is signed and cannot be modified locally.", h->user_name);

                r = user_record_clone(h->record, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE, &c);
                if (r < 0)
                        return r;

                r = user_record_set_disk_size(c, disk_size);
                if (r == -ERANGE)
                        return sd_bus_error_setf(error, BUS_ERROR_BAD_HOME_SIZE, "Requested size for home %s out of acceptable range.", h->user_name);
                if (r < 0)
                        return r;

                /* If user picked an explicit size, then turn off rebalancing, so that we don't undo what user chose */
                r = user_record_set_rebalance_weight(c, REBALANCE_WEIGHT_OFF);
                if (r < 0)
                        return r;

                r = user_record_update_last_changed(c, false);
                if (r == -ECHRNG)
                        return sd_bus_error_setf(error, BUS_ERROR_HOME_RECORD_MISMATCH, "Record last change time of %s is newer than current time, cannot update.", h->user_name);
                if (r < 0)
                        return r;

                r = manager_sign_user_record(h->manager, c, &signed_c, error);
                if (r < 0)
                        return r;

                user_record_unref(c);
                c = TAKE_PTR(signed_c);
        }

        r = home_update_internal(h, automatic ? "resize-auto" : "resize", c, secret, error);
        if (r < 0)
                return r;

        home_set_state(h, HOME_STATE_IS_ACTIVE(state) ? HOME_RESIZING_WHILE_ACTIVE : HOME_RESIZING);
        return 0;
}

static int home_may_change_password(
                Home *h,
                sd_bus_error *error) {

        int r;

        assert(h);

        r = user_record_test_password_change_required(h->record);
        if (IN_SET(r, -EKEYREVOKED, -EOWNERDEAD, -EKEYEXPIRED, -ESTALE))
                return 0; /* expired in some form, but changing is allowed */
        if (IN_SET(r, -EKEYREJECTED, -EROFS))
                return sd_bus_error_setf(error, SD_BUS_ERROR_ACCESS_DENIED, "Expiration settings of account %s do not allow changing of password.", h->user_name);
        if (r < 0)
                return log_error_errno(r, "Failed to test password expiry: %m");

        return 0; /* not expired */
}

int home_passwd(Home *h,
                UserRecord *new_secret,
                UserRecord *old_secret,
                sd_bus_error *error) {

        _cleanup_(user_record_unrefp) UserRecord *c = NULL, *merged_secret = NULL, *signed_c = NULL;
        HomeState state;
        int r;

        assert(h);

        if (h->signed_locally <= 0) /* Don't allow changing of records not signed only by us */
                return sd_bus_error_setf(error, BUS_ERROR_HOME_RECORD_SIGNED, "Home %s is signed and cannot be modified locally.", h->user_name);

        state = home_get_state(h);
        switch (state) {
        case HOME_UNFIXATED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_UNFIXATED, "Home %s has not been fixated yet.", h->user_name);
        case HOME_ABSENT:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_ABSENT, "Home %s is currently missing or not plugged in.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_INACTIVE:
        case HOME_DIRTY:
        case HOME_ACTIVE:
        case HOME_LINGERING:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        r = home_may_change_password(h, error);
        if (r < 0)
                return r;

        r = user_record_clone(h->record, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE, &c);
        if (r < 0)
                return r;

        merged_secret = user_record_new();
        if (!merged_secret)
                return -ENOMEM;

        r = user_record_merge_secret(merged_secret, old_secret);
        if (r < 0)
                return r;

        r = user_record_merge_secret(merged_secret, new_secret);
        if (r < 0)
                return r;

        if (!strv_isempty(new_secret->password)) {
                /* Update the password only if one is specified, otherwise let's just reuse the old password
                 * data. This is useful as a way to propagate updated user records into the LUKS backends
                 * properly. */

                r = user_record_make_hashed_password(c, new_secret->password, /* extend = */ false);
                if (r < 0)
                        return r;

                r = user_record_set_password_change_now(c, -1 /* remove */);
                if (r < 0)
                        return r;
        }

        r = user_record_update_last_changed(c, true);
        if (r == -ECHRNG)
                return sd_bus_error_setf(error, BUS_ERROR_HOME_RECORD_MISMATCH, "Record last change time of %s is newer than current time, cannot update.", h->user_name);
        if (r < 0)
                return r;

        r = manager_sign_user_record(h->manager, c, &signed_c, error);
        if (r < 0)
                return r;

        if (c->enforce_password_policy == false)
                log_debug("Password quality check turned off for account, skipping.");
        else {
                r = user_record_check_password_quality(c, merged_secret, error);
                if (r < 0)
                        return r;
        }

        r = home_update_internal(h, "passwd", signed_c, merged_secret, error);
        if (r < 0)
                return r;

        home_set_state(h, HOME_STATE_IS_ACTIVE(state) ? HOME_PASSWD_WHILE_ACTIVE : HOME_PASSWD);
        return 0;
}

int home_unregister(Home *h, sd_bus_error *error) {
        int r;

        assert(h);

        switch (home_get_state(h)) {
        case HOME_UNFIXATED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_UNFIXATED, "Home %s is not registered.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                break;
        case HOME_ACTIVE:
        case HOME_LINGERING:
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "Home %s is currently being used, or an operation on home %s is currently being executed.", h->user_name, h->user_name);
        }

        r = home_unlink_record(h);
        if (r < 0)
                return r;

        /* And destroy the whole entry. The caller needs to be prepared for that. */
        h = home_free(h);
        return 1;
}

int home_lock(Home *h, sd_bus_error *error) {
        int r;

        assert(h);

        switch (home_get_state(h)) {
        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_NOT_ACTIVE, "Home %s is not active.", h->user_name);
        case HOME_LOCKED:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_LOCKED, "Home %s is already locked.", h->user_name);
        case HOME_ACTIVE:
        case HOME_LINGERING:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        r = home_start_work(h, "lock", h->record, NULL);
        if (r < 0)
                return r;

        home_set_state(h, HOME_LOCKING);
        return 0;
}

static int home_unlock_internal(Home *h, UserRecord *secret, HomeState for_state, sd_bus_error *error) {
        int r;

        assert(h);
        assert(IN_SET(for_state, HOME_UNLOCKING, HOME_UNLOCKING_FOR_ACQUIRE));

        r = home_start_work(h, "unlock", h->record, secret);
        if (r < 0)
                return r;

        home_set_state(h, for_state);
        return 0;
}

int home_unlock(Home *h, UserRecord *secret, sd_bus_error *error) {
        int r;
        assert(h);

        r = home_ratelimit(h, error);
        if (r < 0)
                return r;

        switch (home_get_state(h)) {
        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_ACTIVE:
        case HOME_LINGERING:
        case HOME_DIRTY:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_NOT_LOCKED, "Home %s is not locked.", h->user_name);
        case HOME_LOCKED:
                break;
        default:
                return sd_bus_error_setf(error, BUS_ERROR_HOME_BUSY, "An operation on home %s is currently being executed.", h->user_name);
        }

        return home_unlock_internal(h, secret, HOME_UNLOCKING, error);
}

HomeState home_get_state(Home *h) {
        int r;
        assert(h);

        /* When the state field is initialized, it counts. */
        if (h->state >= 0)
                return h->state;

        /* Otherwise, let's see if the home directory is mounted. If so, we assume for sure the home
         * directory is active */
        if (user_record_test_home_directory(h->record) == USER_TEST_MOUNTED)
                return h->retry_deactivate_event_source ? HOME_LINGERING : HOME_ACTIVE;

        /* And if we see the image being gone, we report this as absent */
        r = user_record_test_image_path(h->record);
        if (r == USER_TEST_ABSENT)
                return HOME_ABSENT;
        if (r == USER_TEST_DIRTY)
                return HOME_DIRTY;

        /* And for all other cases we return "inactive". */
        return HOME_INACTIVE;
}

void home_process_notify(Home *h, char **l, int fd) {
        _cleanup_close_ int taken_fd = TAKE_FD(fd);
        const char *e;
        int error;
        int r;

        assert(h);

        e = strv_env_get(l, "SYSTEMD_LUKS_LOCK_FD");
        if (e) {
                r = parse_boolean(e);
                if (r < 0)
                        return (void) log_debug_errno(r, "Failed to parse SYSTEMD_LUKS_LOCK_FD value: %m");
                if (r > 0) {
                        if (taken_fd < 0)
                                return (void) log_debug("Got notify message with SYSTEMD_LUKS_LOCK_FD=1 but no fd passed, ignoring: %m");

                        close_and_replace(h->luks_lock_fd, taken_fd);

                        log_debug("Successfully acquired LUKS lock fd from worker.");

                        /* Immediately check if we actually want to keep it */
                        home_maybe_close_luks_lock_fd(h, _HOME_STATE_INVALID);
                } else {
                        if (taken_fd >= 0)
                                return (void) log_debug("Got notify message with SYSTEMD_LUKS_LOCK_FD=0 but fd passed, ignoring: %m");

                        h->luks_lock_fd = safe_close(h->luks_lock_fd);
                }

                return;
        }

        e = strv_env_get(l, "ERRNO");
        if (!e)
                return (void) log_debug("Got notify message lacking both ERRNO= and SYSTEMD_LUKS_LOCK_FD= field, ignoring.");

        r = safe_atoi(e, &error);
        if (r < 0)
                return (void) log_debug_errno(r, "Failed to parse received error number, ignoring: %s", e);
        if (error <= 0)
                return (void) log_debug("Error number is out of range: %i", error);

        h->worker_error_code = error;
}

int home_killall(Home *h) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *unit = NULL;
        int r;

        assert(h);

        if (!uid_is_valid(h->uid))
                return 0;

        assert(h->uid > 0); /* We never should be UID 0 */

        /* Let's kill everything matching the specified UID */
        r = safe_fork("(sd-killer)",
                      FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_WAIT|FORK_LOG|FORK_REOPEN_LOG,
                      NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                r = fully_set_uid_gid(h->uid, user_record_gid(h->record), /* supplementary_gids= */ NULL, /* n_supplementary_gids= */ 0);
                if (r < 0) {
                        log_error_errno(r, "Failed to change UID/GID to " UID_FMT "/" GID_FMT ": %m", h->uid, user_record_gid(h->record));
                        _exit(EXIT_FAILURE);
                }

                if (kill(-1, SIGKILL) < 0) {
                        log_error_errno(errno, "Failed to kill all processes of UID " UID_FMT ": %m", h->uid);
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        /* Let's also kill everything in the user's slice */
        if (asprintf(&unit, "user-" UID_FMT ".slice", h->uid) < 0)
                return log_oom();

        r = bus_call_method(h->manager->bus, bus_systemd_mgr, "KillUnit", &error, NULL, "ssi", unit, "all", SIGKILL);
        if (r < 0)
                log_full_errno(sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT) ? LOG_DEBUG : LOG_WARNING,
                               r, "Failed to kill login processes of user, ignoring: %s", bus_error_message(&error, r));

        return 1;
}

static int home_get_disk_status_luks(
                Home *h,
                HomeState state,
                uint64_t *ret_disk_size,
                uint64_t *ret_disk_usage,
                uint64_t *ret_disk_free,
                uint64_t *ret_disk_ceiling,
                uint64_t *ret_disk_floor,
                statfs_f_type_t *ret_fstype,
                mode_t *ret_access_mode) {

        uint64_t disk_size = UINT64_MAX, disk_usage = UINT64_MAX, disk_free = UINT64_MAX,
                disk_ceiling = UINT64_MAX, disk_floor = UINT64_MAX,
                stat_used = UINT64_MAX, fs_size = UINT64_MAX, header_size = 0;
        mode_t access_mode = MODE_INVALID;
        statfs_f_type_t fstype = 0;
        struct statfs sfs;
        struct stat st;
        const char *hd;
        int r;

        assert(h);

        if (state != HOME_ABSENT) {
                const char *ip;

                ip = user_record_image_path(h->record);
                if (ip) {
                        if (stat(ip, &st) < 0)
                                log_debug_errno(errno, "Failed to stat() %s, ignoring: %m", ip);
                        else if (S_ISREG(st.st_mode)) {
                                _cleanup_free_ char *parent = NULL;

                                disk_size = st.st_size;
                                stat_used = st.st_blocks * 512;

                                r = path_extract_directory(ip, &parent);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to extract parent directory from image path '%s': %m", ip);

                                if (statfs(parent, &sfs) < 0)
                                        log_debug_errno(errno, "Failed to statfs() %s, ignoring: %m", parent);
                                else
                                        disk_ceiling = stat_used + sfs.f_bsize * sfs.f_bavail;

                        } else if (S_ISBLK(st.st_mode)) {
                                _cleanup_free_ char *szbuf = NULL;
                                char p[SYS_BLOCK_PATH_MAX("/size")];

                                /* Let's read the size off sysfs, so that we don't have to open the device */
                                xsprintf_sys_block_path(p, "/size", st.st_rdev);
                                r = read_one_line_file(p, &szbuf);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to read %s, ignoring: %m", p);
                                else {
                                        uint64_t sz;

                                        r = safe_atou64(szbuf, &sz);
                                        if (r < 0)
                                                log_debug_errno(r, "Failed to parse %s, ignoring: %s", p, szbuf);
                                        else
                                                disk_size = sz * 512;
                                }
                        } else
                                log_debug("Image path is not a block device or regular file, not able to acquire size.");
                }
        }

        if (!HOME_STATE_IS_ACTIVE(state))
                goto finish;

        hd = user_record_home_directory(h->record);
        if (!hd)
                goto finish;

        if (stat(hd, &st) < 0) {
                log_debug_errno(errno, "Failed to stat() %s, ignoring: %m", hd);
                goto finish;
        }

        r = stat_verify_directory(&st);
        if (r < 0) {
                log_debug_errno(r, "Home directory %s is not a directory, ignoring: %m", hd);
                goto finish;
        }

        access_mode = st.st_mode & 07777;

        if (statfs(hd, &sfs) < 0) {
                log_debug_errno(errno, "Failed to statfs() %s, ignoring: %m", hd);
                goto finish;
        }

        fstype = sfs.f_type;

        disk_free = sfs.f_bsize * sfs.f_bavail;
        fs_size = sfs.f_bsize * sfs.f_blocks;
        if (disk_size != UINT64_MAX && disk_size > fs_size)
                header_size = disk_size - fs_size;

        /* We take a perspective from the user here (as opposed to from the host): the used disk space is the
         * difference from the limit and what's free. This makes a difference if sparse mode is not used: in
         * that case the image is pre-allocated and thus appears all used from the host PoV but is not used
         * up at all yet from the user's PoV.
         *
         * That said, we use the stat() reported loopback file size as upper boundary: our footprint can
         * never be larger than what we take up on the lowest layers. */

        if (disk_size != UINT64_MAX && disk_size > disk_free) {
                disk_usage = disk_size - disk_free;

                if (stat_used != UINT64_MAX && disk_usage > stat_used)
                        disk_usage = stat_used;
        } else
                disk_usage = stat_used;

        /* If we have the magic, determine floor preferably by magic */
        disk_floor = minimal_size_by_fs_magic(sfs.f_type) + header_size;

finish:
        /* If we don't know the magic, go by file system name */
        if (disk_floor == UINT64_MAX)
                disk_floor = minimal_size_by_fs_name(user_record_file_system_type(h->record));

        if (ret_disk_size)
                *ret_disk_size = disk_size;
        if (ret_disk_usage)
                *ret_disk_usage = disk_usage;
        if (ret_disk_free)
                *ret_disk_free = disk_free;
        if (ret_disk_ceiling)
                *ret_disk_ceiling = disk_ceiling;
        if (ret_disk_floor)
                *ret_disk_floor = disk_floor;
        if (ret_fstype)
                *ret_fstype = fstype;
        if (ret_access_mode)
                *ret_access_mode = access_mode;

        return 0;
}

static int home_get_disk_status_directory(
                Home *h,
                HomeState state,
                uint64_t *ret_disk_size,
                uint64_t *ret_disk_usage,
                uint64_t *ret_disk_free,
                uint64_t *ret_disk_ceiling,
                uint64_t *ret_disk_floor,
                statfs_f_type_t *ret_fstype,
                mode_t *ret_access_mode) {

        uint64_t disk_size = UINT64_MAX, disk_usage = UINT64_MAX, disk_free = UINT64_MAX,
                disk_ceiling = UINT64_MAX, disk_floor = UINT64_MAX;
        mode_t access_mode = MODE_INVALID;
        statfs_f_type_t fstype = 0;
        struct statfs sfs;
        struct dqblk req;
        const char *path = NULL;
        int r;

        assert(h);

        if (HOME_STATE_IS_ACTIVE(state))
                path = user_record_home_directory(h->record);

        if (!path) {
                if (state == HOME_ABSENT)
                        goto finish;

                path = user_record_image_path(h->record);
        }

        if (!path)
                goto finish;

        if (statfs(path, &sfs) < 0)
                log_debug_errno(errno, "Failed to statfs() %s, ignoring: %m", path);
        else {
                disk_free = sfs.f_bsize * sfs.f_bavail;
                disk_size = sfs.f_bsize * sfs.f_blocks;

                /* We don't initialize disk_usage from statfs() data here, since the device is likely not used
                 * by us alone, and disk_usage should only reflect our own use. */

                fstype = sfs.f_type;
        }

        if (IN_SET(h->record->storage, USER_CLASSIC, USER_DIRECTORY, USER_SUBVOLUME)) {

                r = btrfs_is_subvol(path);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine whether %s is a btrfs subvolume: %m", path);
                else if (r > 0) {
                        BtrfsQuotaInfo qi;

                        r = btrfs_subvol_get_subtree_quota(path, 0, &qi);
                        if (r < 0)
                                log_debug_errno(r, "Failed to query btrfs subtree quota, ignoring: %m");
                        else {
                                disk_usage = qi.referenced;

                                if (disk_free != UINT64_MAX) {
                                        disk_ceiling = qi.referenced + disk_free;

                                        if (disk_size != UINT64_MAX && disk_ceiling > disk_size)
                                                disk_ceiling = disk_size;
                                }

                                if (qi.referenced_max != UINT64_MAX) {
                                        if (disk_size != UINT64_MAX)
                                                disk_size = MIN(qi.referenced_max, disk_size);
                                        else
                                                disk_size = qi.referenced_max;
                                }

                                if (disk_size != UINT64_MAX) {
                                        if (disk_size > disk_usage)
                                                disk_free = disk_size - disk_usage;
                                        else
                                                disk_free = 0;
                                }
                        }

                        goto finish;
                }
        }

        if (IN_SET(h->record->storage, USER_CLASSIC, USER_DIRECTORY, USER_FSCRYPT)) {
                r = quotactl_path(QCMD_FIXED(Q_GETQUOTA, USRQUOTA), path, h->uid, &req);
                if (r < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(r)) {
                                log_debug_errno(r, "No UID quota support on %s.", path);
                                goto finish;
                        }

                        if (r != -ESRCH) {
                                log_debug_errno(r, "Failed to query disk quota for UID " UID_FMT ": %m", h->uid);
                                goto finish;
                        }

                        disk_usage = 0; /* No record of this user? then nothing was used */
                } else {
                        if (FLAGS_SET(req.dqb_valid, QIF_SPACE) && disk_free != UINT64_MAX) {
                                disk_ceiling = req.dqb_curspace + disk_free;

                                if (disk_size != UINT64_MAX && disk_ceiling > disk_size)
                                        disk_ceiling = disk_size;
                        }

                        if (FLAGS_SET(req.dqb_valid, QIF_BLIMITS)) {
                                uint64_t q;

                                /* Take the minimum of the quota and the available disk space here */
                                q = req.dqb_bhardlimit * QIF_DQBLKSIZE;
                                if (disk_size != UINT64_MAX)
                                        disk_size = MIN(disk_size, q);
                                else
                                        disk_size = q;
                        }
                        if (FLAGS_SET(req.dqb_valid, QIF_SPACE)) {
                                disk_usage = req.dqb_curspace;

                                if (disk_size != UINT64_MAX) {
                                        if (disk_size > disk_usage)
                                                disk_free = disk_size - disk_usage;
                                        else
                                                disk_free = 0;
                                }
                        }
                }
        }

finish:
        if (ret_disk_size)
                *ret_disk_size = disk_size;
        if (ret_disk_usage)
                *ret_disk_usage = disk_usage;
        if (ret_disk_free)
                *ret_disk_free = disk_free;
        if (ret_disk_ceiling)
                *ret_disk_ceiling = disk_ceiling;
        if (ret_disk_floor)
                *ret_disk_floor = disk_floor;
        if (ret_fstype)
                *ret_fstype = fstype;
        if (ret_access_mode)
                *ret_access_mode = access_mode;

        return 0;
}

static int home_get_disk_status_internal(
                Home *h,
                HomeState state,
                uint64_t *ret_disk_size,
                uint64_t *ret_disk_usage,
                uint64_t *ret_disk_free,
                uint64_t *ret_disk_ceiling,
                uint64_t *ret_disk_floor,
                statfs_f_type_t *ret_fstype,
                mode_t *ret_access_mode) {

        assert(h);
        assert(h->record);

        switch (h->record->storage) {

        case USER_LUKS:
                return home_get_disk_status_luks(h, state, ret_disk_size, ret_disk_usage, ret_disk_free, ret_disk_ceiling, ret_disk_floor, ret_fstype, ret_access_mode);

        case USER_CLASSIC:
        case USER_DIRECTORY:
        case USER_SUBVOLUME:
        case USER_FSCRYPT:
        case USER_CIFS:
                return home_get_disk_status_directory(h, state, ret_disk_size, ret_disk_usage, ret_disk_free, ret_disk_ceiling, ret_disk_floor, ret_fstype, ret_access_mode);

        default:
                /* don't know */

                if (ret_disk_size)
                        *ret_disk_size = UINT64_MAX;
                if (ret_disk_usage)
                        *ret_disk_usage = UINT64_MAX;
                if (ret_disk_free)
                        *ret_disk_free = UINT64_MAX;
                if (ret_disk_ceiling)
                        *ret_disk_ceiling = UINT64_MAX;
                if (ret_disk_floor)
                        *ret_disk_floor = UINT64_MAX;
                if (ret_fstype)
                        *ret_fstype = 0;
                if (ret_access_mode)
                        *ret_access_mode = MODE_INVALID;

                return 0;
        }
}

int home_get_disk_status(
                Home *h,
                uint64_t *ret_disk_size,
                uint64_t *ret_disk_usage,
                uint64_t *ret_disk_free,
                uint64_t *ret_disk_ceiling,
                uint64_t *ret_disk_floor,
                statfs_f_type_t *ret_fstype,
                mode_t *ret_access_mode) {

        assert(h);

        return home_get_disk_status_internal(
                        h,
                        home_get_state(h),
                        ret_disk_size,
                        ret_disk_usage,
                        ret_disk_free,
                        ret_disk_ceiling,
                        ret_disk_floor,
                        ret_fstype,
                        ret_access_mode);
}

int home_augment_status(
                Home *h,
                UserRecordLoadFlags flags,
                UserRecord **ret) {

        uint64_t disk_size = UINT64_MAX, disk_usage = UINT64_MAX, disk_free = UINT64_MAX, disk_ceiling = UINT64_MAX, disk_floor = UINT64_MAX;
        _cleanup_(json_variant_unrefp) JsonVariant *j = NULL, *v = NULL, *m = NULL, *status = NULL;
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        statfs_f_type_t magic;
        const char *fstype;
        mode_t access_mode;
        HomeState state;
        sd_id128_t id;
        int r;

        assert(h);
        assert(ret);

        /* We are supposed to add this, this can't be on hence. */
        assert(!FLAGS_SET(flags, USER_RECORD_STRIP_STATUS));

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        state = home_get_state(h);

        r = home_get_disk_status_internal(
                        h, state,
                        &disk_size,
                        &disk_usage,
                        &disk_free,
                        &disk_ceiling,
                        &disk_floor,
                        &magic,
                        &access_mode);
        if (r < 0)
                return r;

        fstype = fs_type_to_string(magic);

        if (disk_floor == UINT64_MAX || (disk_usage != UINT64_MAX && disk_floor < disk_usage))
                disk_floor = disk_usage;
        if (disk_floor == UINT64_MAX || disk_floor < USER_DISK_SIZE_MIN)
                disk_floor = USER_DISK_SIZE_MIN;
        if (disk_ceiling == UINT64_MAX || disk_ceiling > USER_DISK_SIZE_MAX)
                disk_ceiling = USER_DISK_SIZE_MAX;

        r = json_build(&status,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("state", JSON_BUILD_STRING(home_state_to_string(state))),
                                       JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.Home")),
                                       JSON_BUILD_PAIR_CONDITION(disk_size != UINT64_MAX, "diskSize", JSON_BUILD_UNSIGNED(disk_size)),
                                       JSON_BUILD_PAIR_CONDITION(disk_usage != UINT64_MAX, "diskUsage", JSON_BUILD_UNSIGNED(disk_usage)),
                                       JSON_BUILD_PAIR_CONDITION(disk_free != UINT64_MAX, "diskFree", JSON_BUILD_UNSIGNED(disk_free)),
                                       JSON_BUILD_PAIR_CONDITION(disk_ceiling != UINT64_MAX, "diskCeiling", JSON_BUILD_UNSIGNED(disk_ceiling)),
                                       JSON_BUILD_PAIR_CONDITION(disk_floor != UINT64_MAX, "diskFloor", JSON_BUILD_UNSIGNED(disk_floor)),
                                       JSON_BUILD_PAIR_CONDITION(h->signed_locally >= 0, "signedLocally", JSON_BUILD_BOOLEAN(h->signed_locally)),
                                       JSON_BUILD_PAIR_CONDITION(fstype, "fileSystemType", JSON_BUILD_STRING(fstype)),
                                       JSON_BUILD_PAIR_CONDITION(access_mode != MODE_INVALID, "accessMode", JSON_BUILD_UNSIGNED(access_mode))
                       ));
        if (r < 0)
                return r;

        j = json_variant_ref(h->record->json);
        v = json_variant_ref(json_variant_by_key(j, "status"));
        m = json_variant_ref(json_variant_by_key(v, SD_ID128_TO_STRING(id)));

        r = json_variant_filter(&m, STRV_MAKE("diskSize", "diskUsage", "diskFree", "diskCeiling", "diskFloor", "signedLocally"));
        if (r < 0)
                return r;

        r = json_variant_merge_object(&m, status);
        if (r < 0)
                return r;

        r = json_variant_set_field(&v, SD_ID128_TO_STRING(id), m);
        if (r < 0)
                return r;

        r = json_variant_set_field(&j, "status", v);
        if (r < 0)
                return r;

        ur = user_record_new();
        if (!ur)
                return -ENOMEM;

        r = user_record_load(ur, j, flags);
        if (r < 0)
                return r;

        ur->incomplete =
                FLAGS_SET(h->record->mask, USER_RECORD_PRIVILEGED) &&
                !FLAGS_SET(ur->mask, USER_RECORD_PRIVILEGED);

        *ret = TAKE_PTR(ur);
        return 0;
}

static int on_home_ref_eof(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(operation_unrefp) Operation *o = NULL;
        Home *h = ASSERT_PTR(userdata);

        assert(s);

        if (h->ref_event_source_please_suspend == s)
                h->ref_event_source_please_suspend = sd_event_source_disable_unref(h->ref_event_source_please_suspend);

        if (h->ref_event_source_dont_suspend == s)
                h->ref_event_source_dont_suspend = sd_event_source_disable_unref(h->ref_event_source_dont_suspend);

        if (h->ref_event_source_dont_suspend || h->ref_event_source_please_suspend)
                return 0;

        log_info("Got notification that all sessions of user %s ended, deactivating automatically.", h->user_name);

        o = operation_new(OPERATION_PIPE_EOF, NULL);
        if (!o) {
                log_oom();
                return 0;
        }

        home_schedule_operation(h, o, NULL);
        return 0;
}

int home_create_fifo(Home *h, bool please_suspend) {
        _cleanup_close_ int ret_fd = -EBADF;
        sd_event_source **ss;
        const char *fn, *suffix;
        int r;

        assert(h);

        if (please_suspend) {
                suffix = ".please-suspend";
                ss = &h->ref_event_source_please_suspend;
        } else {
                suffix = ".dont-suspend";
                ss = &h->ref_event_source_dont_suspend;
        }

        fn = strjoina("/run/systemd/home/", h->user_name, suffix);

        if (!*ss) {
                _cleanup_close_ int ref_fd = -EBADF;

                (void) mkdir("/run/systemd/home/", 0755);
                if (mkfifo(fn, 0600) < 0 && errno != EEXIST)
                        return log_error_errno(errno, "Failed to create FIFO %s: %m", fn);

                ref_fd = open(fn, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (ref_fd < 0)
                        return log_error_errno(errno, "Failed to open FIFO %s for reading: %m", fn);

                r = sd_event_add_io(h->manager->event, ss, ref_fd, 0, on_home_ref_eof, h);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate reference FIFO event source: %m");

                (void) sd_event_source_set_description(*ss, "acquire-ref");

                r = sd_event_source_set_priority(*ss, SD_EVENT_PRIORITY_IDLE-1);
                if (r < 0)
                        return r;

                r = sd_event_source_set_io_fd_own(*ss, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to pass ownership of FIFO event fd to event source: %m");

                TAKE_FD(ref_fd);
        }

        ret_fd = open(fn, O_WRONLY|O_CLOEXEC|O_NONBLOCK);
        if (ret_fd < 0)
                return log_error_errno(errno, "Failed to open FIFO %s for writing: %m", fn);

        return TAKE_FD(ret_fd);
}

static int home_dispatch_acquire(Home *h, Operation *o) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int (*call)(Home *h, UserRecord *secret, HomeState for_state, sd_bus_error *error) = NULL;
        HomeState for_state;
        int r;

        assert(h);
        assert(o);
        assert(o->type == OPERATION_ACQUIRE);

        switch (home_get_state(h)) {

        case HOME_UNFIXATED:
                for_state = HOME_FIXATING_FOR_ACQUIRE;
                call = home_fixate_internal;
                break;

        case HOME_ABSENT:
                r = sd_bus_error_setf(&error, BUS_ERROR_HOME_ABSENT,
                                      "Home %s is currently missing or not plugged in.", h->user_name);
                goto check;

        case HOME_INACTIVE:
        case HOME_DIRTY:
                for_state = HOME_ACTIVATING_FOR_ACQUIRE;
                call = home_activate_internal;
                break;

        case HOME_ACTIVE:
        case HOME_LINGERING:
                for_state = HOME_AUTHENTICATING_FOR_ACQUIRE;
                call = home_authenticate_internal;
                break;

        case HOME_LOCKED:
                for_state = HOME_UNLOCKING_FOR_ACQUIRE;
                call = home_unlock_internal;
                break;

        default:
                /* All other cases means we are currently executing an operation, which means the job remains
                 * pending. */
                return 0;
        }

        assert(!h->current_operation);

        r = home_ratelimit(h, &error);
        if (r >= 0)
                r = call(h, o->secret, for_state, &error);

 check:
        if (r != 0) /* failure or completed */
                operation_result(o, r, &error);
        else /* ongoing */
                h->current_operation = operation_ref(o);

        return 1;
}

static int home_dispatch_release(Home *h, Operation *o) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(o);
        assert(o->type == OPERATION_RELEASE);

        if (h->ref_event_source_dont_suspend || h->ref_event_source_please_suspend)
                /* If there's now a reference again, then let's abort the release attempt */
                r = sd_bus_error_setf(&error, BUS_ERROR_HOME_BUSY, "Home %s is currently referenced.", h->user_name);
        else {
                switch (home_get_state(h)) {

                case HOME_UNFIXATED:
                case HOME_ABSENT:
                case HOME_INACTIVE:
                case HOME_DIRTY:
                        r = 1; /* done */
                        break;

                case HOME_LOCKED:
                        r = sd_bus_error_setf(&error, BUS_ERROR_HOME_LOCKED, "Home %s is currently locked.", h->user_name);
                        break;

                case HOME_ACTIVE:
                case HOME_LINGERING:
                        r = home_deactivate_internal(h, false, &error);
                        break;

                default:
                        /* All other cases means we are currently executing an operation, which means the job remains
                         * pending. */
                        return 0;
                }
        }

        assert(!h->current_operation);

        if (r != 0) /* failure or completed */
                operation_result(o, r, &error);
        else /* ongoing */
                h->current_operation = operation_ref(o);

        return 1;
}

static int home_dispatch_lock_all(Home *h, Operation *o) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(o);
        assert(o->type == OPERATION_LOCK_ALL);

        switch (home_get_state(h)) {

        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                log_info("Home %s is not active, no locking necessary.", h->user_name);
                r = 1; /* done */
                break;

        case HOME_LOCKED:
                log_info("Home %s is already locked.", h->user_name);
                r = 1; /* done */
                break;

        case HOME_ACTIVE:
        case HOME_LINGERING:
                log_info("Locking home %s.", h->user_name);
                r = home_lock(h, &error);
                break;

        default:
                /* All other cases means we are currently executing an operation, which means the job remains
                 * pending. */
                return 0;
        }

        assert(!h->current_operation);

        if (r != 0) /* failure or completed */
                operation_result(o, r, &error);
        else /* ongoing */
                h->current_operation = operation_ref(o);

        return 1;
}

static int home_dispatch_deactivate_all(Home *h, Operation *o) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(o);
        assert(o->type == OPERATION_DEACTIVATE_ALL);

        switch (home_get_state(h)) {

        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                log_info("Home %s is already deactivated.", h->user_name);
                r = 1; /* done */
                break;

        case HOME_LOCKED:
                log_info("Home %s is currently locked, not deactivating.", h->user_name);
                r = 1; /* done */
                break;

        case HOME_ACTIVE:
        case HOME_LINGERING:
                log_info("Deactivating home %s.", h->user_name);
                r = home_deactivate_internal(h, false, &error);
                break;

        default:
                /* All other cases means we are currently executing an operation, which means the job remains
                 * pending. */
                return 0;
        }

        assert(!h->current_operation);

        if (r != 0) /* failure or completed */
                operation_result(o, r, &error);
        else /* ongoing */
                h->current_operation = operation_ref(o);

        return 1;
}

static int home_dispatch_pipe_eof(Home *h, Operation *o) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(o);
        assert(o->type == OPERATION_PIPE_EOF);

        if (h->ref_event_source_please_suspend || h->ref_event_source_dont_suspend)
                return 1; /* Hmm, there's a reference again, let's cancel this */

        switch (home_get_state(h)) {

        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                log_info("Home %s already deactivated, no automatic deactivation needed.", h->user_name);
                break;

        case HOME_DEACTIVATING:
                log_info("Home %s is already being deactivated, automatic deactivated unnecessary.", h->user_name);
                break;

        case HOME_ACTIVE:
        case HOME_LINGERING:
                r = home_deactivate_internal(h, false, &error);
                if (r < 0)
                        log_warning_errno(r, "Failed to deactivate %s, ignoring: %s", h->user_name, bus_error_message(&error, r));
                break;

        case HOME_LOCKED:
        default:
                /* If the device is locked or any operation is being executed, let's leave this pending */
                return 0;
        }

        /* Note that we don't call operation_fail() or operation_success() here, because this kind of
         * operation has no message associated with it, and thus there's no need to propagate success. */

        assert(!o->message);
        return 1;
}

static int home_dispatch_deactivate_force(Home *h, Operation *o) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(h);
        assert(o);
        assert(o->type == OPERATION_DEACTIVATE_FORCE);

        switch (home_get_state(h)) {

        case HOME_UNFIXATED:
        case HOME_ABSENT:
        case HOME_INACTIVE:
        case HOME_DIRTY:
                log_debug("Home %s already deactivated, no forced deactivation due to unplug needed.", h->user_name);
                break;

        case HOME_DEACTIVATING:
                log_debug("Home %s is already being deactivated, forced deactivation due to unplug unnecessary.", h->user_name);
                break;

        case HOME_ACTIVE:
        case HOME_LOCKED:
        case HOME_LINGERING:
                r = home_deactivate_internal(h, true, &error);
                if (r < 0)
                        log_warning_errno(r, "Failed to forcibly deactivate %s, ignoring: %s", h->user_name, bus_error_message(&error, r));
                break;

        default:
                /* If any operation is being executed, let's leave this pending */
                return 0;
        }

        /* Note that we don't call operation_fail() or operation_success() here, because this kind of
         * operation has no message associated with it, and thus there's no need to propagate success. */

        assert(!o->message);
        return 1;
}

static int on_pending(sd_event_source *s, void *userdata) {
        Home *h = ASSERT_PTR(userdata);
        Operation *o;
        int r;

        assert(s);

        o = ordered_set_first(h->pending_operations);
        if (o) {
                static int (* const operation_table[_OPERATION_MAX])(Home *h, Operation *o) = {
                        [OPERATION_ACQUIRE]          = home_dispatch_acquire,
                        [OPERATION_RELEASE]          = home_dispatch_release,
                        [OPERATION_LOCK_ALL]         = home_dispatch_lock_all,
                        [OPERATION_DEACTIVATE_ALL]   = home_dispatch_deactivate_all,
                        [OPERATION_PIPE_EOF]         = home_dispatch_pipe_eof,
                        [OPERATION_DEACTIVATE_FORCE] = home_dispatch_deactivate_force,
                };

                assert(operation_table[o->type]);
                r = operation_table[o->type](h, o);
                if (r != 0) {
                        /* The operation completed, let's remove it from the pending list, and exit while
                         * leaving the event source enabled as it is. */
                        assert_se(ordered_set_remove(h->pending_operations, o) == o);
                        operation_unref(o);
                        return 0;
                }
        }

        /* Nothing to do anymore, let's turn off this event source */
        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to disable event source: %m");

        /* No operations pending anymore, maybe this is a good time to trigger a rebalancing */
        manager_reschedule_rebalance(h->manager);
        return 0;
}

int home_schedule_operation(Home *h, Operation *o, sd_bus_error *error) {
        int r;

        assert(h);

        if (o) {
                if (ordered_set_size(h->pending_operations) >= PENDING_OPERATIONS_MAX)
                        return sd_bus_error_set(error, BUS_ERROR_TOO_MANY_OPERATIONS, "Too many client operations requested");

                r = ordered_set_ensure_put(&h->pending_operations, &operation_hash_ops, o);
                if (r < 0)
                        return r;

                operation_ref(o);
        }

        if (!h->pending_event_source) {
                r = sd_event_add_defer(h->manager->event, &h->pending_event_source, on_pending, h);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate pending defer event source: %m");

                (void) sd_event_source_set_description(h->pending_event_source, "pending");

                r = sd_event_source_set_priority(h->pending_event_source, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        return r;
        }

        r = sd_event_source_set_enabled(h->pending_event_source, SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to trigger pending event source: %m");

        return 0;
}

static int home_get_image_path_seat(Home *h, char **ret) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *c = NULL;
        const char *ip, *seat;
        struct stat st;
        int r;

        assert(h);

        if (user_record_storage(h->record) != USER_LUKS)
                return -ENXIO;

        ip = user_record_image_path(h->record);
        if (!ip)
                return -ENXIO;

        if (!path_startswith(ip, "/dev/"))
                return -ENXIO;

        if (stat(ip, &st) < 0)
                return -errno;

        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0)
                return r;

        r = sd_device_get_property_value(d, "ID_SEAT", &seat);
        if (r == -ENOENT) /* no property means seat0 */
                seat = "seat0";
        else if (r < 0)
                return r;

        c = strdup(seat);
        if (!c)
                return -ENOMEM;

        *ret = TAKE_PTR(c);
        return 0;
}

int home_auto_login(Home *h, char ***ret_seats) {
        _cleanup_free_ char *seat = NULL, *seat2 = NULL;

        assert(h);
        assert(ret_seats);

        (void) home_get_image_path_seat(h, &seat);

        if (h->record->auto_login > 0 && !streq_ptr(seat, "seat0")) {
                /* For now, when the auto-login boolean is set for a user, let's make it mean
                 * "seat0". Eventually we can extend the concept and allow configuration of any kind of seat,
                 * but let's keep simple initially, most likely the feature is interesting on single-user
                 * systems anyway, only.
                 *
                 * We filter out users marked for auto-login in we know for sure their home directory is
                 * absent. */

                if (user_record_test_image_path(h->record) != USER_TEST_ABSENT) {
                        seat2 = strdup("seat0");
                        if (!seat2)
                                return -ENOMEM;
                }
        }

        if (seat || seat2) {
                _cleanup_strv_free_ char **list = NULL;
                size_t i = 0;

                list = new(char*, 3);
                if (!list)
                        return -ENOMEM;

                if (seat)
                        list[i++] = TAKE_PTR(seat);
                if (seat2)
                        list[i++] = TAKE_PTR(seat2);

                list[i] = NULL;
                *ret_seats = TAKE_PTR(list);
                return 1;
        }

        *ret_seats = NULL;
        return 0;
}

int home_set_current_message(Home *h, sd_bus_message *m) {
        assert(h);

        if (!m)
                return 0;

        if (h->current_operation)
                return -EBUSY;

        h->current_operation = operation_new(OPERATION_IMMEDIATE, m);
        if (!h->current_operation)
                return -ENOMEM;

        return 1;
}

int home_wait_for_worker(Home *h) {
        int r;

        assert(h);

        if (h->worker_pid <= 0)
                return 0;

        log_info("Worker process for home %s is still running while exiting. Waiting for it to finish.", h->user_name);

        r = wait_for_terminate_with_timeout(h->worker_pid, 30 * USEC_PER_SEC);
        if (r == -ETIMEDOUT)
                log_warning_errno(r, "Waiting for worker process for home %s timed out. Ignoring.", h->user_name);
        else if (r < 0)
                log_warning_errno(r, "Failed to wait for worker process for home %s. Ignoring.", h->user_name);

        (void) hashmap_remove_value(h->manager->homes_by_worker_pid, PID_TO_PTR(h->worker_pid), h);
        h->worker_pid = 0;
        return 1;
}

bool home_shall_rebalance(Home *h) {
        HomeState state;

        assert(h);

        /* Determines if the home directory is a candidate for rebalancing */

        if (!user_record_shall_rebalance(h->record))
                return false;

        state = home_get_state(h);
        if (!HOME_STATE_SHALL_REBALANCE(state))
                return false;

        return true;
}

bool home_is_busy(Home *h) {
        assert(h);

        if (h->current_operation)
                return true;

        if (!ordered_set_isempty(h->pending_operations))
                return true;

        return HOME_STATE_IS_EXECUTING_OPERATION(home_get_state(h));
}

static const char* const home_state_table[_HOME_STATE_MAX] = {
        [HOME_UNFIXATED]                   = "unfixated",
        [HOME_ABSENT]                      = "absent",
        [HOME_INACTIVE]                    = "inactive",
        [HOME_DIRTY]                       = "dirty",
        [HOME_FIXATING]                    = "fixating",
        [HOME_FIXATING_FOR_ACTIVATION]     = "fixating-for-activation",
        [HOME_FIXATING_FOR_ACQUIRE]        = "fixating-for-acquire",
        [HOME_ACTIVATING]                  = "activating",
        [HOME_ACTIVATING_FOR_ACQUIRE]      = "activating-for-acquire",
        [HOME_DEACTIVATING]                = "deactivating",
        [HOME_ACTIVE]                      = "active",
        [HOME_LINGERING]                   = "lingering",
        [HOME_LOCKING]                     = "locking",
        [HOME_LOCKED]                      = "locked",
        [HOME_UNLOCKING]                   = "unlocking",
        [HOME_UNLOCKING_FOR_ACQUIRE]       = "unlocking-for-acquire",
        [HOME_CREATING]                    = "creating",
        [HOME_REMOVING]                    = "removing",
        [HOME_UPDATING]                    = "updating",
        [HOME_UPDATING_WHILE_ACTIVE]       = "updating-while-active",
        [HOME_RESIZING]                    = "resizing",
        [HOME_RESIZING_WHILE_ACTIVE]       = "resizing-while-active",
        [HOME_PASSWD]                      = "passwd",
        [HOME_PASSWD_WHILE_ACTIVE]         = "passwd-while-active",
        [HOME_AUTHENTICATING]              = "authenticating",
        [HOME_AUTHENTICATING_WHILE_ACTIVE] = "authenticating-while-active",
        [HOME_AUTHENTICATING_FOR_ACQUIRE]  = "authenticating-for-acquire",
};

DEFINE_STRING_TABLE_LOOKUP(home_state, HomeState);
