/* SPDX-License-Identifier: LGPL-2.1+ */

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "errno-util.h"
#include "fd-util.h"
#include "home-util.h"
#include "memory-util.h"
#include "pam-util.h"
#include "parse-util.h"
#include "strv.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"

/* Used for the "systemd-user-record-is-homed" PAM data field, to indicate whether we know whether this user
 * record is managed by homed or by something else. */
#define USER_RECORD_IS_HOMED INT_TO_PTR(1)
#define USER_RECORD_IS_OTHER INT_TO_PTR(2)

static int parse_argv(
                pam_handle_t *handle,
                int argc, const char **argv,
                bool *please_suspend,
                bool *debug) {

        int i;

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (i = 0; i < argc; i++) {
                const char *v;

                if ((v = startswith(argv[i], "suspend="))) {
                        int k;

                        k = parse_boolean(v);
                        if (k < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse suspend= argument, ignoring: %s", v);
                        else if (please_suspend)
                                *please_suspend = k;

                } else if ((v = startswith(argv[i], "debug="))) {
                        int k;

                        k = parse_boolean(v);
                        if (k < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse debug= argument, ignoring: %s", v);
                        else if (debug)
                                *debug = k;

                } else
                        pam_syslog(handle, LOG_WARNING, "Unknown parameter '%s', ignoring", argv[i]);
        }

        return 0;
}

static int acquire_user_record(
                pam_handle_t *handle,
                UserRecord **ret_record) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        const char *username = NULL, *json = NULL;
        const void *b = NULL;
        int r;

        assert(handle);

        r = pam_get_user(handle, &username, NULL);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to get user name: %s", pam_strerror(handle, r));
                return r;
        }

        if (isempty(username)) {
                pam_syslog(handle, LOG_ERR, "User name not set.");
                return PAM_SERVICE_ERR;
        }

        /* Let's bypass all IPC complexity for the two user names we know for sure we don't manage, and for
         * user names we don't consider valid. */
        if (STR_IN_SET(username, "root", NOBODY_USER_NAME) || !valid_user_group_name(username, 0))
                return PAM_USER_UNKNOWN;

        /* Let's check if a previous run determined that this user is not managed by homed. If so, let's exit early */
        r = pam_get_data(handle, "systemd-user-record-is-homed", &b);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA)) {
                /* Failure */
                pam_syslog(handle, LOG_ERR, "Failed to get PAM user-record-is-homed flag: %s", pam_strerror(handle, r));
                return r;
        } else if (b == NULL)
                /* Nothing cached yet, need to acquire fresh */
                json = NULL;
        else if (b != USER_RECORD_IS_HOMED)
                /* Definitely not a homed record */
                return PAM_USER_UNKNOWN;
        else {
                /* It's a homed record, let's use the cache, so that we can share it between the session and
                 * the authentication hooks */
                r = pam_get_data(handle, "systemd-user-record", (const void**) &json);
                if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA)) {
                        pam_syslog(handle, LOG_ERR, "Failed to get PAM user record data: %s", pam_strerror(handle, r));
                        return r;
                }
        }

        if (!json) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *json_copy = NULL;

                r = pam_acquire_bus_connection(handle, &bus);
                if (r != PAM_SUCCESS)
                        return r;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "GetUserRecordByName",
                                &error,
                                &reply,
                                "s",
                                username);
                if (r < 0) {
                        if (sd_bus_error_has_name(&error, SD_BUS_ERROR_SERVICE_UNKNOWN) ||
                            sd_bus_error_has_name(&error, SD_BUS_ERROR_NAME_HAS_NO_OWNER)) {
                                pam_syslog(handle, LOG_DEBUG, "systemd-homed is not available: %s", bus_error_message(&error, r));
                                goto user_unknown;
                        }

                        if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_HOME)) {
                                pam_syslog(handle, LOG_DEBUG, "Not a user managed by systemd-homed: %s", bus_error_message(&error, r));
                                goto user_unknown;
                        }

                        pam_syslog(handle, LOG_ERR, "Failed to query user record: %s", bus_error_message(&error, r));
                        return PAM_SERVICE_ERR;
                }

                r = sd_bus_message_read(reply, "sbo", &json, NULL, NULL);
                if (r < 0)
                        return pam_bus_log_parse_error(handle, r);

                json_copy = strdup(json);
                if (!json_copy)
                        return pam_log_oom(handle);

                r = pam_set_data(handle, "systemd-user-record", json_copy, pam_cleanup_free);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set PAM user record data: %s", pam_strerror(handle, r));
                        return r;
                }

                TAKE_PTR(json_copy);

                r = pam_set_data(handle, "systemd-user-record-is-homed", USER_RECORD_IS_HOMED, NULL);
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to set PAM user record is homed flag: %s", pam_strerror(handle, r));
                        return r;
                }
        }

        r = json_parse(json, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to parse JSON user record: %s", strerror_safe(r));
                return PAM_SERVICE_ERR;
        }

        ur = user_record_new();
        if (!ur)
                return pam_log_oom(handle);

        r = user_record_load(ur, v, USER_RECORD_LOAD_REFUSE_SECRET);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to load user record: %s", strerror_safe(r));
                return PAM_SERVICE_ERR;
        }

        if (!streq_ptr(username, ur->user_name)) {
                pam_syslog(handle, LOG_ERR, "Acquired user record does not match user name.");
                return PAM_SERVICE_ERR;
        }

        if (ret_record)
                *ret_record = TAKE_PTR(ur);

        return PAM_SUCCESS;

user_unknown:
        /* Cache this, so that we don't check again */
        r = pam_set_data(handle, "systemd-user-record-is-homed", USER_RECORD_IS_OTHER, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "Failed to set PAM user-record-is-homed flag, ignoring: %s", pam_strerror(handle, r));

        return PAM_USER_UNKNOWN;
}

static int release_user_record(pam_handle_t *handle) {
        int r, k;

        r = pam_set_data(handle, "systemd-user-record", NULL, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "Failed to release PAM user record data: %s", pam_strerror(handle, r));

        k = pam_set_data(handle, "systemd-user-record-is-homed", NULL, NULL);
        if (k != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "Failed to release PAM user-record-is-homed flag: %s", pam_strerror(handle, k));

        return IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA) ? k : r;
}

static void cleanup_home_fd(pam_handle_t *handle, void *data, int error_status) {
        safe_close(PTR_TO_FD(data));
}

static int handle_generic_user_record_error(
                pam_handle_t *handle,
                const char *user_name,
                UserRecord *secret,
                int ret,
                const sd_bus_error *error) {

        assert(user_name);
        assert(secret);
        assert(error);

        int r;

        /* Logs about all errors, except for PAM_CONV_ERR, i.e. when requesting more info failed. */

        if (sd_bus_error_has_name(error, BUS_ERROR_HOME_ABSENT)) {
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Home of user %s is currently absent, please plug in the necessary storage device or backing file system.", user_name);
                pam_syslog(handle, LOG_ERR, "Failed to acquire home for user %s: %s", user_name, bus_error_message(error, ret));
                return PAM_PERM_DENIED;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_AUTHENTICATION_LIMIT_HIT)) {
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Too frequent unsuccessful login attempts for user %s, try again later.", user_name);
                pam_syslog(handle, LOG_ERR, "Failed to acquire home for user %s: %s", user_name, bus_error_message(error, ret));
                return PAM_MAXTRIES;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_PASSWORD)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                /* This didn't work? Ask for an (additional?) password */

                if (strv_isempty(secret->password))
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Password: ");
                else
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Password incorrect or not sufficient for authentication of user %s, please try again: ", user_name);
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_syslog(handle, LOG_DEBUG, "Password request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_password(secret, STRV_MAKE(newp), true);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store password: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                if (strv_isempty(secret->password))
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Security token of user %s not inserted, please enter password: ", user_name);
                else
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Password incorrect or not sufficient, and configured security token of user %s not inserted, please enter password: ", user_name);
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_syslog(handle, LOG_DEBUG, "Password request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_password(secret, STRV_MAKE(newp), true);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store password: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PIN_NEEDED)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Please enter security token PIN: ");
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_syslog(handle, LOG_DEBUG, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_pkcs11_pin(secret, STRV_MAKE(newp), false);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store PIN: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PROTECTED_AUTHENTICATION_PATH_NEEDED)) {

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Please authenticate physically on security token of user %s.", user_name);

                r = user_record_set_pkcs11_protected_authentication_path_permitted(secret, true);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to set PKCS#11 protected authentication path permitted flag: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Security token PIN incorrect, please enter PIN for security token of user %s again: ", user_name);
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_syslog(handle, LOG_DEBUG, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_pkcs11_pin(secret, STRV_MAKE(newp), false);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store PIN: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN_FEW_TRIES_LEFT)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Security token PIN incorrect (only a few tries left!), please enter PIN for security token of user %s again: ", user_name);
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_syslog(handle, LOG_DEBUG, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_pkcs11_pin(secret, STRV_MAKE(newp), false);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store PIN: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN_ONE_TRY_LEFT)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, "Security token PIN incorrect (only one try left!), please enter PIN for security token of user %s again: ", user_name);
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_syslog(handle, LOG_DEBUG, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_pkcs11_pin(secret, STRV_MAKE(newp), false);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store PIN: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }

        } else {
                pam_syslog(handle, LOG_ERR, "Failed to acquire home for user %s: %s", user_name, bus_error_message(error, ret));
                return PAM_SERVICE_ERR;
        }

        return PAM_SUCCESS;
}

static int acquire_home(
                pam_handle_t *handle,
                bool please_authenticate,
                bool please_suspend,
                bool debug) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL, *secret = NULL;
        bool do_auth = please_authenticate, home_not_active = false, home_locked = false;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int acquired_fd = -1;
        const void *home_fd_ptr = NULL;
        unsigned n_attempts = 0;
        int r;

        assert(handle);

        /* This acquires a reference to a home directory in one of two ways: if please_authenticate is true,
         * then we'll call AcquireHome() after asking the user for a password. Otherwise it tries to call
         * RefHome() and if that fails queries the user for a password and uses AcquireHome().
         *
         * The idea is that the PAM authentication hook sets please_authenticate and thus always
         * authenticates, while the other PAM hooks unset it so that they can a ref of their own without
         * authentication if possible, but with authentication if necessary. */

        /* If we already have acquired the fd, let's shortcut this */
        r = pam_get_data(handle, "systemd-home-fd", &home_fd_ptr);
        if (r == PAM_SUCCESS && PTR_TO_INT(home_fd_ptr) >= 0)
                return PAM_SUCCESS;

        r = pam_acquire_bus_connection(handle, &bus);
        if (r != PAM_SUCCESS)
                return r;

        r = acquire_user_record(handle, &ur);
        if (r != PAM_SUCCESS)
                return r;

        /* Implement our own retry loop here instead of relying on the PAM client's one. That's because it
         * might happen that the the record we stored on the host does not match the encryption password of
         * the LUKS image in case the image was used in a different system where the password was
         * changed. In that case it will happen that the LUKS password and the host password are
         * different, and we handle that by collecting and passing multiple passwords in that case. Hence we
         * treat bad passwords as a request to collect one more password and pass the new all all previously
         * used passwords again. */

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                if (do_auth && !secret) {
                        const char *cached_password = NULL;

                        secret = user_record_new();
                        if (!secret)
                                return pam_log_oom(handle);

                        /* If there's already a cached password, use it. But if not let's authenticate
                         * without anything, maybe some other authentication mechanism systemd-homed
                         * implements (such as PKCS#11) allows us to authenticate without anything else. */
                        r = pam_get_item(handle, PAM_AUTHTOK, (const void**) &cached_password);
                        if (!IN_SET(r, PAM_BAD_ITEM, PAM_SUCCESS)) {
                                pam_syslog(handle, LOG_ERR, "Failed to get cached password: %s", pam_strerror(handle, r));
                                return r;
                        }

                        if (!isempty(cached_password)) {
                                r = user_record_set_password(secret, STRV_MAKE(cached_password), true);
                                if (r < 0) {
                                        pam_syslog(handle, LOG_ERR, "Failed to store password: %s", strerror_safe(r));
                                        return PAM_SERVICE_ERR;
                                }
                        }
                }

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                do_auth ? "AcquireHome" : "RefHome");
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                r = sd_bus_message_append(m, "s", ur->user_name);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                if (do_auth) {
                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return pam_bus_log_create_error(handle, r);
                }

                r = sd_bus_message_append(m, "b", please_suspend);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
                if (r < 0) {

                        if (sd_bus_error_has_name(&error, BUS_ERROR_HOME_NOT_ACTIVE))
                                /* Only on RefHome(): We can't access the home directory currently, unless
                                 * it's unlocked with a password. Hence, let's try this again, this time with
                                 * authentication. */
                                home_not_active = true;
                        else if (sd_bus_error_has_name(&error, BUS_ERROR_HOME_LOCKED))
                                home_locked = true; /* Similar */
                        else {
                                r = handle_generic_user_record_error(handle, ur->user_name, secret, r, &error);
                                if (r == PAM_CONV_ERR) {
                                        /* Password/PIN prompts will fail in certain environments, for example when
                                         * we are called from OpenSSH's account or session hooks, or in systemd's
                                         * per-service PAM logic. In that case, print a friendly message and accept
                                         * failure. */

                                        if (home_not_active)
                                                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Home of user %s is currently not active, please log in locally first.", ur->user_name);
                                        if (home_locked)
                                                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Home of user %s is currently locked, please unlock locally first.", ur->user_name);

                                        pam_syslog(handle, please_authenticate ? LOG_ERR : LOG_DEBUG, "Failed to prompt for password/prompt.");

                                        return home_not_active || home_locked ? PAM_PERM_DENIED : PAM_CONV_ERR;
                                }
                                if (r != PAM_SUCCESS)
                                        return r;
                        }

                } else {
                        int fd;

                        r = sd_bus_message_read(reply, "h", &fd);
                        if (r < 0)
                                return pam_bus_log_parse_error(handle, r);

                        acquired_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                        if (acquired_fd < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to duplicate acquired fd: %s", bus_error_message(&error, r));
                                return PAM_SERVICE_ERR;
                        }

                        break;
                }

                if (++n_attempts >= 5) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Too many unsuccessful login attempts for user %s, refusing.", ur->user_name);
                        pam_syslog(handle, LOG_ERR, "Failed to acquire home for user %s: %s", ur->user_name, bus_error_message(&error, r));
                        return PAM_MAXTRIES;
                }

                /* Try again, this time with authentication if we didn't do that before. */
                do_auth = true;
        }

        r = pam_set_data(handle, "systemd-home-fd", FD_TO_PTR(acquired_fd), cleanup_home_fd);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to set PAM bus data: %s", pam_strerror(handle, r));
                return r;
        }
        TAKE_FD(acquired_fd);

        if (do_auth) {
                /* We likely just activated the home directory, let's flush out the user record, since a
                 * newer embedded user record might have been acquired from the activation. */

                r = release_user_record(handle);
                if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                        return r;
        }

        pam_syslog(handle, LOG_NOTICE, "Home for user %s successfully acquired.", ur->user_name);

        return PAM_SUCCESS;
}

static int release_home_fd(pam_handle_t *handle) {
        const void *home_fd_ptr = NULL;
        int r;

        r = pam_get_data(handle, "systemd-home-fd", &home_fd_ptr);
        if (r == PAM_NO_MODULE_DATA || PTR_TO_FD(home_fd_ptr) < 0)
                return PAM_NO_MODULE_DATA;

        r = pam_set_data(handle, "systemd-home-fd", NULL, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog(handle, LOG_ERR, "Failed to release PAM home reference fd: %s", pam_strerror(handle, r));

        return r;
}

_public_ PAM_EXTERN int pam_sm_authenticate(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        bool debug = false, suspend_please = false;

        if (parse_argv(handle,
                       argc, argv,
                       &suspend_please,
                       &debug) < 0)
                return PAM_AUTH_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd-homed authenticating");

        return acquire_home(handle, /* please_authenticate= */ true, suspend_please, debug);
}

_public_ PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        bool debug = false, suspend_please = false;
        int r;

        if (parse_argv(handle,
                       argc, argv,
                       &suspend_please,
                       &debug) < 0)
                return PAM_SESSION_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd-homed session start");

        r = acquire_home(handle, /* please_authenticate = */ false, suspend_please, debug);
        if (r == PAM_USER_UNKNOWN) /* Not managed by us? Don't complain. */
                return PAM_SUCCESS;
        if (r != PAM_SUCCESS)
                return r;

        r = pam_putenv(handle, "SYSTEMD_HOME=1");
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set PAM environment variable $SYSTEMD_HOME: %s", pam_strerror(handle, r));
                return r;
        }

        /* Let's release the D-Bus connection, after all the session might live quite a long time, and we are
         * not going to process the bus connection in that time, so let's better close before the daemon
         * kicks us off because we are not processing anything. */
        (void) pam_release_bus_connection(handle);
        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_close_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        const char *username = NULL;
        bool debug = false;
        int r;

        if (parse_argv(handle,
                       argc, argv,
                       NULL,
                       &debug) < 0)
                return PAM_SESSION_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd-homed session end");

        /* Let's explicitly drop the reference to the homed session, so that the subsequent ReleaseHome()
         * call will be able to do its thing. */
        r = release_home_fd(handle);
        if (r == PAM_NO_MODULE_DATA) /* Nothing to do, we never acquired an fd */
                return PAM_SUCCESS;
        if (r != PAM_SUCCESS)
                return r;

        r = pam_get_user(handle, &username, NULL);
        if (r != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to get user name: %s", pam_strerror(handle, r));
                return r;
        }

        r = pam_acquire_bus_connection(handle, &bus);
        if (r != PAM_SUCCESS)
                return r;

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "ReleaseHome");
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_message_append(m, "s", username);
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_HOME_BUSY))
                        pam_syslog(handle, LOG_NOTICE, "Not deactivating home directory of %s, as it is still used.", username);
                else {
                        pam_syslog(handle, LOG_ERR, "Failed to release user home: %s", bus_error_message(&error, r));
                        return PAM_SESSION_ERR;
                }
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_acct_mgmt(
                pam_handle_t *handle,
                int flags,
                int argc,
                const char **argv) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        bool debug = false, please_suspend = false;
        usec_t t;
        int r;

        if (parse_argv(handle,
                       argc, argv,
                       &please_suspend,
                       &debug) < 0)
                return PAM_AUTH_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd-homed account management");

        r = acquire_home(handle, /* please_authenticate = */ false, please_suspend, debug);
        if (r == PAM_USER_UNKNOWN)
                return PAM_SUCCESS; /* we don't have anything to say about users we don't manage */
        if (r != PAM_SUCCESS)
                return r;

        r = acquire_user_record(handle, &ur);
        if (r != PAM_SUCCESS)
                return r;

        r = user_record_test_blocked(ur);
        switch (r) {

        case -ESTALE:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "User record is newer than current system time, prohibiting access.");
                return PAM_ACCT_EXPIRED;

        case -ENOLCK:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "User record is blocked, prohibiting access.");
                return PAM_ACCT_EXPIRED;

        case -EL2HLT:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "User record is not valid yet, prohibiting access.");
                return PAM_ACCT_EXPIRED;

        case -EL3HLT:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "User record is not valid anymore, prohibiting access.");
                return PAM_ACCT_EXPIRED;

        default:
                if (r < 0) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "User record not valid, prohibiting access.");
                        return PAM_ACCT_EXPIRED;
                }

                break;
        }

        t = user_record_ratelimit_next_try(ur);
        if (t != USEC_INFINITY) {
                usec_t n = now(CLOCK_REALTIME);

                if (t > n) {
                        char buf[FORMAT_TIMESPAN_MAX];
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Too many logins, try again in %s.",
                                          format_timespan(buf, sizeof(buf), t - n, USEC_PER_SEC));

                        return PAM_MAXTRIES;
                }
        }

        r = user_record_test_password_change_required(ur);
        switch (r) {

        case -EKEYREVOKED:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Password change required.");
                return PAM_NEW_AUTHTOK_REQD;

        case -EOWNERDEAD:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Password expired, change requird.");
                return PAM_NEW_AUTHTOK_REQD;

        case -EKEYREJECTED:
                /* Strictly speaking this is only about password expiration, and we might want to allow
                 * authentication via PKCS#11 or so, but let's ignore this fine distinction for now. */
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Password is expired, but can't change, refusing login.");
                return PAM_AUTHTOK_EXPIRED;

        case -EKEYEXPIRED:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "Password will expire soon, please change.");
                break;

        case -EROFS:
                /* All good, just means the password if we wanted to change we couldn't, but we don't need to */
                break;

        default:
                if (r < 0) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, "User record not valid, prohibiting access.");
                        return PAM_AUTHTOK_EXPIRED;
                }

                break;
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_chauthtok(
                pam_handle_t *handle,
                int flags,
                int argc,
                const char **argv) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL, *old_secret = NULL, *new_secret = NULL;
        const char *old_password = NULL, *new_password = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        unsigned n_attempts = 0;
        bool debug = false;
        int r;

        if (parse_argv(handle,
                       argc, argv,
                       NULL,
                       &debug) < 0)
                return PAM_AUTH_ERR;

        if (debug)
                pam_syslog(handle, LOG_DEBUG, "pam-systemd-homed account management");

        r = pam_acquire_bus_connection(handle, &bus);
        if (r != PAM_SUCCESS)
                return r;

        r = acquire_user_record(handle, &ur);
        if (r != PAM_SUCCESS)
                return r;

        /* Start with cached credentials */
        r = pam_get_item(handle, PAM_OLDAUTHTOK, (const void**) &old_password);
        if (!IN_SET(r, PAM_BAD_ITEM, PAM_SUCCESS)) {
                pam_syslog(handle, LOG_ERR, "Failed to get old password: %s", pam_strerror(handle, r));
                return r;
        }
        r = pam_get_item(handle, PAM_AUTHTOK, (const void**) &new_password);
        if (!IN_SET(r, PAM_BAD_ITEM, PAM_SUCCESS)) {
                pam_syslog(handle, LOG_ERR, "Failed to get cached password: %s", pam_strerror(handle, r));
                return r;
        }

        if (isempty(new_password)) {
                /* No, it's not cached, then let's ask for the password and its verification, and cache
                 * it. */

                r = pam_get_authtok_noverify(handle, &new_password, "New password: ");
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to get new password: %s", pam_strerror(handle, r));
                        return r;
                }
                if (isempty(new_password)) {
                        pam_syslog(handle, LOG_DEBUG, "Password request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = pam_get_authtok_verify(handle, &new_password, "new password: "); /* Lower case, since PAM prefixes 'Repeat' */
                if (r != PAM_SUCCESS) {
                        pam_syslog(handle, LOG_ERR, "Failed to get password again: %s", pam_strerror(handle, r));
                        return r;
                }

                // FIXME: pam_pwquality will ask for the password a third time. It really shouldn't do
                // that, and instead assume the password was already verified once when it is found to be
                // cached already. needs to be fixed in pam_pwquality
        }

        /* Now everything is cached and checked, let's exit from the preliminary check */
        if (FLAGS_SET(flags, PAM_PRELIM_CHECK))
                return PAM_SUCCESS;


        old_secret = user_record_new();
        if (!old_secret)
                return pam_log_oom(handle);

        if (!isempty(old_password)) {
                r = user_record_set_password(old_secret, STRV_MAKE(old_password), true);
                if (r < 0) {
                        pam_syslog(handle, LOG_ERR, "Failed to store old password: %s", strerror_safe(r));
                        return PAM_SERVICE_ERR;
                }
        }

        new_secret = user_record_new();
        if (!new_secret)
                return pam_log_oom(handle);

        r = user_record_set_password(new_secret, STRV_MAKE(new_password), true);
        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to store new password: %s", strerror_safe(r));
                return PAM_SERVICE_ERR;
        }

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.home1",
                                "/org/freedesktop/home1",
                                "org.freedesktop.home1.Manager",
                                "ChangePasswordHome");
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                r = sd_bus_message_append(m, "s", ur->user_name);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                r = bus_message_append_secret(m, new_secret);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                r = bus_message_append_secret(m, old_secret);
                if (r < 0)
                        return pam_bus_log_create_error(handle, r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        r = handle_generic_user_record_error(handle, ur->user_name, old_secret, r, &error);
                        if (r == PAM_CONV_ERR) {
                                pam_syslog(handle, LOG_ERR, "Failed to prompt for password/prompt.");
                                return PAM_CONV_ERR;
                        }
                        if (r != PAM_SUCCESS)
                                return r;
                } else {
                        pam_syslog(handle, LOG_NOTICE, "Successfully changed password for user %s.", ur->user_name);
                        return PAM_SUCCESS;
                }

                if (++n_attempts >= 5)
                        break;

                /* Try again */
        };

        pam_syslog(handle, LOG_NOTICE, "Failed to change password for user %s: %m", ur->user_name);
        return PAM_MAXTRIES;
}
