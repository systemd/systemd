/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "sd-bus.h"

#include "bus-common-errors.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "home-util.h"
#include "locale-util.h"
#include "memory-util.h"
#include "pam-util.h"
#include "parse-util.h"
#include "strv.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"

typedef enum AcquireHomeFlags {
        ACQUIRE_MUST_AUTHENTICATE = 1 << 0,
        ACQUIRE_PLEASE_SUSPEND    = 1 << 1,
} AcquireHomeFlags;

static int parse_argv(
                pam_handle_t *handle,
                int argc, const char **argv,
                AcquireHomeFlags *flags,
                bool *debug) {

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (int i = 0; i < argc; i++) {
                const char *v;

                if ((v = startswith(argv[i], "suspend="))) {
                        int k;

                        k = parse_boolean(v);
                        if (k < 0)
                                pam_syslog(handle, LOG_WARNING, "Failed to parse suspend= argument, ignoring: %s", v);
                        else if (flags)
                                SET_FLAG(*flags, ACQUIRE_PLEASE_SUSPEND, k);

                } else if (streq(argv[i], "debug")) {
                        if (debug)
                                *debug = true;

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

static int parse_env(
                pam_handle_t *handle,
                AcquireHomeFlags *flags) {

        const char *v;
        int r;

        /* Let's read the suspend setting from an env var in addition to the PAM command line. That makes it
         * easy to declare the features of a display manager in code rather than configuration, and this is
         * really a feature of code */

        v = pam_getenv(handle, "SYSTEMD_HOME_SUSPEND");
        if (!v) {
                /* Also check the process env block, so that people can control this via an env var from the
                 * outside of our process. */
                v = secure_getenv("SYSTEMD_HOME_SUSPEND");
                if (!v)
                        return 0;
        }

        r = parse_boolean(v);
        if (r < 0)
                pam_syslog(handle, LOG_WARNING, "Failed to parse $SYSTEMD_HOME_SUSPEND argument, ignoring: %s", v);
        else if (flags)
                SET_FLAG(*flags, ACQUIRE_PLEASE_SUSPEND, r);

        return 0;
}

static int acquire_user_record(
                pam_handle_t *handle,
                const char *username,
                bool debug,
                UserRecord **ret_record,
                PamBusData **bus_data) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *homed_field = NULL;
        const char *json = NULL;
        int r;

        assert(handle);

        if (!username) {
                r = pam_get_user(handle, &username, NULL);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get user name: @PAMERR@");

                if (isempty(username))
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR, "User name not set.");
        }

        /* Let's bypass all IPC complexity for the two user names we know for sure we don't manage, and for
         * user names we don't consider valid. */
        if (STR_IN_SET(username, "root", NOBODY_USER_NAME) || !valid_user_group_name(username, 0))
                return PAM_USER_UNKNOWN;

        /* We cache the user record in the PAM context. We use a field name that includes the username, since
         * clients might change the user name associated with a PAM context underneath us. Notably, 'sudo'
         * creates a single PAM context and first authenticates it with the user set to the originating user,
         * then updates the user for the destination user and issues the session stack with the same PAM
         * context. We thus must be prepared that the user record changes between calls and we keep any
         * caching separate. */
        homed_field = strjoin("systemd-home-user-record-", username);
        if (!homed_field)
                return pam_log_oom(handle);

        /* Let's use the cache, so that we can share it between the session and the authentication hooks */
        r = pam_get_data(handle, homed_field, (const void**) &json);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get PAM user record data: @PAMERR@");
        if (r == PAM_SUCCESS && json) {
                /* We determined earlier that this is not a homed user? Then exit early. (We use -1 as
                 * negative cache indicator) */
                if (json == POINTER_MAX)
                        return PAM_USER_UNKNOWN;
        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *generic_field = NULL, *json_copy = NULL;

                r = pam_acquire_bus_connection(handle, "pam-systemd-home", &bus, bus_data);
                if (r != PAM_SUCCESS)
                        return r;

                r = bus_call_method(bus, bus_home_mgr, "GetUserRecordByName", &error, &reply, "s", username);
                if (r < 0) {
                        if (bus_error_is_unknown_service(&error)) {
                                pam_debug_syslog(handle, debug,
                                                 "systemd-homed is not available: %s",
                                                 bus_error_message(&error, r));
                                goto user_unknown;
                        }

                        if (sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_HOME)) {
                                pam_debug_syslog(handle, debug,
                                                 "Not a user managed by systemd-homed: %s",
                                                 bus_error_message(&error, r));
                                goto user_unknown;
                        }

                        pam_syslog(handle, LOG_ERR,
                                   "Failed to query user record: %s", bus_error_message(&error, r));
                        return PAM_SERVICE_ERR;
                }

                r = sd_bus_message_read(reply, "sbo", &json, NULL, NULL);
                if (r < 0)
                        return pam_bus_log_parse_error(handle, r);

                /* First copy: for the homed-specific data field, i.e. where we know the user record is from
                 * homed */
                json_copy = strdup(json);
                if (!json_copy)
                        return pam_log_oom(handle);

                r = pam_set_data(handle, homed_field, json_copy, pam_cleanup_free);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r,
                                                    "Failed to set PAM user record data '%s': @PAMERR@", homed_field);

                /* Take a second copy: for the generic data field, the one which we share with
                 * pam_systemd. While we insist on only reusing homed records, pam_systemd is fine with homed
                 * and non-homed user records. */
                json_copy = strdup(json);
                if (!json_copy)
                        return pam_log_oom(handle);

                generic_field = strjoin("systemd-user-record-", username);
                if (!generic_field)
                        return pam_log_oom(handle);

                r = pam_set_data(handle, generic_field, json_copy, pam_cleanup_free);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r,
                                                    "Failed to set PAM user record data '%s': @PAMERR@", homed_field);

                TAKE_PTR(json_copy);
        }

        r = json_parse(json, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to parse JSON user record: %m");

        ur = user_record_new();
        if (!ur)
                return pam_log_oom(handle);

        r = user_record_load(ur, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to load user record: %m");

        /* Safety check if cached record actually matches what we are looking for */
        if (!streq_ptr(username, ur->user_name))
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR,
                                            "Acquired user record does not match user name.");

        if (ret_record)
                *ret_record = TAKE_PTR(ur);

        return PAM_SUCCESS;

user_unknown:
        /* Cache this, so that we don't check again */
        r = pam_set_data(handle, homed_field, POINTER_MAX, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog_pam_error(handle, LOG_ERR, r,
                                     "Failed to set PAM user record data '%s' to invalid, ignoring: @PAMERR@",
                                     homed_field);

        return PAM_USER_UNKNOWN;
}

static int release_user_record(pam_handle_t *handle, const char *username) {
        _cleanup_free_ char *homed_field = NULL, *generic_field = NULL;
        int r, k;

        assert(handle);
        assert(username);

        homed_field = strjoin("systemd-home-user-record-", username);
        if (!homed_field)
                return pam_log_oom(handle);

        r = pam_set_data(handle, homed_field, NULL, NULL);
        if (r != PAM_SUCCESS)
                pam_syslog_pam_error(handle, LOG_ERR, r,
                                     "Failed to release PAM user record data '%s': @PAMERR@", homed_field);

        generic_field = strjoin("systemd-user-record-", username);
        if (!generic_field)
                return pam_log_oom(handle);

        k = pam_set_data(handle, generic_field, NULL, NULL);
        if (k != PAM_SUCCESS)
                pam_syslog_pam_error(handle, LOG_ERR, k,
                                     "Failed to release PAM user record data '%s': @PAMERR@", generic_field);

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
                const sd_bus_error *error,
                bool debug) {

        assert(user_name);
        assert(error);

        int r;

        /* Logs about all errors, except for PAM_CONV_ERR, i.e. when requesting more info failed. */

        if (sd_bus_error_has_name(error, BUS_ERROR_HOME_ABSENT)) {
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL,
                                  _("Home of user %s is currently absent, please plug in the necessary storage device or backing file system."), user_name);
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_PERM_DENIED,
                                            "Failed to acquire home for user %s: %s", user_name, bus_error_message(error, ret));

        } else if (sd_bus_error_has_name(error, BUS_ERROR_AUTHENTICATION_LIMIT_HIT)) {
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Too frequent login attempts for user %s, try again later."), user_name);
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_MAXTRIES,
                                            "Failed to acquire home for user %s: %s", user_name, bus_error_message(error, ret));

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_PASSWORD)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                /* This didn't work? Ask for an (additional?) password */

                if (strv_isempty(secret->password))
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Password: "));
                else {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password incorrect or not sufficient for authentication of user %s."), user_name);
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Sorry, try again: "));
                }
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "Password request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_password(secret, STRV_MAKE(newp), true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store password: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_RECOVERY_KEY)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                /* Hmm, homed asks for recovery key (because no regular password is defined maybe)? Provide it. */

                if (strv_isempty(secret->password))
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Recovery key: "));
                else {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password/recovery key incorrect or not sufficient for authentication of user %s."), user_name);
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Sorry, reenter recovery key: "));
                }
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "Recovery key request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_password(secret, STRV_MAKE(newp), true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store recovery key: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                if (strv_isempty(secret->password)) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Security token of user %s not inserted."), user_name);
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Try again with password: "));
                } else {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password incorrect or not sufficient, and configured security token of user %s not inserted."), user_name);
                        r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Try again with password: "));
                }
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "Password request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_password(secret, STRV_MAKE(newp), true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store password: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PIN_NEEDED)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Security token PIN: "));
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_token_pin(secret, STRV_MAKE(newp), false);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store PIN: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PROTECTED_AUTHENTICATION_PATH_NEEDED)) {

                assert(secret);

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Please authenticate physically on security token of user %s."), user_name);

                r = user_record_set_pkcs11_protected_authentication_path_permitted(secret, true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r,
                                                "Failed to set PKCS#11 protected authentication path permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_USER_PRESENCE_NEEDED)) {

                assert(secret);

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Please confirm presence on security token of user %s."), user_name);

                r = user_record_set_fido2_user_presence_permitted(secret, true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r,
                                                "Failed to set FIDO2 user presence permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_USER_VERIFICATION_NEEDED)) {

                assert(secret);

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Please verify user on security token of user %s."), user_name);

                r = user_record_set_fido2_user_verification_permitted(secret, true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r,
                                                "Failed to set FIDO2 user verification permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PIN_LOCKED)) {

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Security token PIN is locked, please unlock it first. (Hint: Removal and re-insertion might suffice.)"));
                return PAM_SERVICE_ERR;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Security token PIN incorrect for user %s."), user_name);
                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Sorry, retry security token PIN: "));
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_token_pin(secret, STRV_MAKE(newp), false);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store PIN: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN_FEW_TRIES_LEFT)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Security token PIN of user %s incorrect (only a few tries left!)"), user_name);
                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Sorry, retry security token PIN: "));
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_token_pin(secret, STRV_MAKE(newp), false);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store PIN: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN_ONE_TRY_LEFT)) {
                _cleanup_(erase_and_freep) char *newp = NULL;

                assert(secret);

                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Security token PIN of user %s incorrect (only one try left!)"), user_name);
                r = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, &newp, _("Sorry, retry security token PIN: "));
                if (r != PAM_SUCCESS)
                        return PAM_CONV_ERR; /* no logging here */

                if (isempty(newp)) {
                        pam_debug_syslog(handle, debug, "PIN request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = user_record_set_token_pin(secret, STRV_MAKE(newp), false);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store PIN: %m");

        } else
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR,
                                            "Failed to acquire home for user %s: %s", user_name, bus_error_message(error, ret));

        return PAM_SUCCESS;
}

static int acquire_home(
                pam_handle_t *handle,
                AcquireHomeFlags flags,
                bool debug,
                PamBusData **bus_data) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL, *secret = NULL;
        bool do_auth = FLAGS_SET(flags, ACQUIRE_MUST_AUTHENTICATE), home_not_active = false, home_locked = false;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int acquired_fd = -EBADF;
        _cleanup_free_ char *fd_field = NULL;
        const void *home_fd_ptr = NULL;
        const char *username = NULL;
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

        r = pam_get_user(handle, &username, NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get user name: @PAMERR@");

        if (isempty(username))
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR, "User name not set.");

        /* If we already have acquired the fd, let's shortcut this */
        fd_field = strjoin("systemd-home-fd-", username);
        if (!fd_field)
                return pam_log_oom(handle);

        r = pam_get_data(handle, fd_field, &home_fd_ptr);
        if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to retrieve PAM home reference fd: @PAMERR@");
        if (r == PAM_SUCCESS && PTR_TO_FD(home_fd_ptr) >= 0)
                return PAM_SUCCESS;

        r = pam_acquire_bus_connection(handle, "pam-systemd-home", &bus, bus_data);
        if (r != PAM_SUCCESS)
                return r;

        r = acquire_user_record(handle, username, debug, &ur, bus_data);
        if (r != PAM_SUCCESS)
                return r;

        /* Implement our own retry loop here instead of relying on the PAM client's one. That's because it
         * might happen that the record we stored on the host does not match the encryption password of
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
                        if (!IN_SET(r, PAM_BAD_ITEM, PAM_SUCCESS))
                                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                                            "Failed to get cached password: @PAMERR@");

                        if (!isempty(cached_password)) {
                                r = user_record_set_password(secret, STRV_MAKE(cached_password), true);
                                if (r < 0)
                                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store password: %m");
                        }
                }

                r = bus_message_new_method_call(bus, &m, bus_home_mgr, do_auth ? "AcquireHome" : "RefHome");
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

                r = sd_bus_message_append(m, "b", FLAGS_SET(flags, ACQUIRE_PLEASE_SUSPEND));
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
                                r = handle_generic_user_record_error(handle, ur->user_name, secret, r, &error, debug);
                                if (r == PAM_CONV_ERR) {
                                        /* Password/PIN prompts will fail in certain environments, for example when
                                         * we are called from OpenSSH's account or session hooks, or in systemd's
                                         * per-service PAM logic. In that case, print a friendly message and accept
                                         * failure. */

                                        if (home_not_active)
                                                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Home of user %s is currently not active, please log in locally first."), ur->user_name);
                                        if (home_locked)
                                                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Home of user %s is currently locked, please unlock locally first."), ur->user_name);

                                        if (FLAGS_SET(flags, ACQUIRE_MUST_AUTHENTICATE) || debug)
                                                pam_syslog(handle, FLAGS_SET(flags, ACQUIRE_MUST_AUTHENTICATE) ? LOG_ERR : LOG_DEBUG, "Failed to prompt for password/prompt.");

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
                        if (acquired_fd < 0)
                                return pam_syslog_errno(handle, LOG_ERR, errno,
                                                        "Failed to duplicate acquired fd: %m");
                        break;
                }

                if (++n_attempts >= 5) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL,
                                          _("Too many unsuccessful login attempts for user %s, refusing."), ur->user_name);
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_MAXTRIES,
                                                    "Failed to acquire home for user %s: %s", ur->user_name, bus_error_message(&error, r));
                }

                /* Try again, this time with authentication if we didn't do that before. */
                do_auth = true;
        }

        /* Later PAM modules may need the auth token, but only during pam_authenticate. */
        if (FLAGS_SET(flags, ACQUIRE_MUST_AUTHENTICATE) && !strv_isempty(secret->password)) {
                r = pam_set_item(handle, PAM_AUTHTOK, *secret->password);
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set PAM auth token: @PAMERR@");
        }

        r = pam_set_data(handle, fd_field, FD_TO_PTR(acquired_fd), cleanup_home_fd);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to set PAM bus data: @PAMERR@");
        TAKE_FD(acquired_fd);

        if (do_auth) {
                /* We likely just activated the home directory, let's flush out the user record, since a
                 * newer embedded user record might have been acquired from the activation. */

                r = release_user_record(handle, ur->user_name);
                if (!IN_SET(r, PAM_SUCCESS, PAM_NO_MODULE_DATA))
                        return r;
        }

        pam_syslog(handle, LOG_NOTICE, "Home for user %s successfully acquired.", ur->user_name);
        return PAM_SUCCESS;
}

static int release_home_fd(pam_handle_t *handle, const char *username) {
        _cleanup_free_ char *fd_field = NULL;
        const void *home_fd_ptr = NULL;
        int r;

        assert(handle);
        assert(username);

        fd_field = strjoin("systemd-home-fd-", username);
        if (!fd_field)
                return pam_log_oom(handle);

        r = pam_get_data(handle, fd_field, &home_fd_ptr);
        if (r == PAM_NO_MODULE_DATA || (r == PAM_SUCCESS && PTR_TO_FD(home_fd_ptr) < 0))
                return PAM_NO_MODULE_DATA;
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to retrieve PAM home reference fd: @PAMERR@");

        r = pam_set_data(handle, fd_field, NULL, NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to release PAM home reference fd: @PAMERR@");

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_authenticate(
                pam_handle_t *handle,
                int sm_flags,
                int argc, const char **argv) {

        AcquireHomeFlags flags = 0;
        bool debug = false;

        if (parse_env(handle, &flags) < 0)
                return PAM_AUTH_ERR;

        if (parse_argv(handle,
                       argc, argv,
                       &flags,
                       &debug) < 0)
                return PAM_AUTH_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd-homed authenticating");

        return acquire_home(handle, ACQUIRE_MUST_AUTHENTICATE|flags, debug, /* bus_data= */ NULL);
}

_public_ PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int sm_flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int sm_flags,
                int argc, const char **argv) {

        /* Let's release the D-Bus connection once this function exits, after all the session might live
         * quite a long time, and we are not going to process the bus connection in that time, so let's
         * better close before the daemon kicks us off because we are not processing anything. */
        _cleanup_(pam_bus_data_disconnectp) PamBusData *d = NULL;
        AcquireHomeFlags flags = 0;
        bool debug = false;
        int r;

        if (parse_env(handle, &flags) < 0)
                return PAM_SESSION_ERR;

        if (parse_argv(handle,
                       argc, argv,
                       &flags,
                       &debug) < 0)
                return PAM_SESSION_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd-homed session start");

        r = acquire_home(handle, flags, debug, &d);
        if (r == PAM_USER_UNKNOWN) /* Not managed by us? Don't complain. */
                return PAM_SUCCESS;
        if (r != PAM_SUCCESS)
                return r;

        r = pam_putenv(handle, "SYSTEMD_HOME=1");
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set PAM environment variable $SYSTEMD_HOME: @PAMERR@");

        r = pam_putenv(handle, FLAGS_SET(flags, ACQUIRE_PLEASE_SUSPEND) ? "SYSTEMD_HOME_SUSPEND=1" : "SYSTEMD_HOME_SUSPEND=0");
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                            "Failed to set PAM environment variable $SYSTEMD_HOME_SUSPEND: @PAMERR@");

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_close_session(
                pam_handle_t *handle,
                int sm_flags,
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

        pam_debug_syslog(handle, debug, "pam-systemd-homed session end");

        r = pam_get_user(handle, &username, NULL);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get user name: @PAMERR@");

        if (isempty(username))
                return pam_syslog_pam_error(handle, LOG_ERR, PAM_SERVICE_ERR, "User name not set.");

        /* Let's explicitly drop the reference to the homed session, so that the subsequent ReleaseHome()
         * call will be able to do its thing. */
        r = release_home_fd(handle, username);
        if (r == PAM_NO_MODULE_DATA) /* Nothing to do, we never acquired an fd */
                return PAM_SUCCESS;
        if (r != PAM_SUCCESS)
                return r;

        r = pam_acquire_bus_connection(handle, "pam-systemd-home", &bus, NULL);
        if (r != PAM_SUCCESS)
                return r;

        r = bus_message_new_method_call(bus, &m, bus_home_mgr, "ReleaseHome");
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_message_append(m, "s", username);
        if (r < 0)
                return pam_bus_log_create_error(handle, r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0) {
                if (!sd_bus_error_has_name(&error, BUS_ERROR_HOME_BUSY))
                        return pam_syslog_pam_error(handle, LOG_ERR, PAM_SESSION_ERR,
                                                    "Failed to release user home: %s", bus_error_message(&error, r));

                pam_syslog(handle, LOG_NOTICE, "Not deactivating home directory of %s, as it is still used.", username);
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_acct_mgmt(
                pam_handle_t *handle,
                int sm_flags,
                int argc,
                const char **argv) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        AcquireHomeFlags flags = 0;
        bool debug = false;
        usec_t t;
        int r;

        if (parse_env(handle, &flags) < 0)
                return PAM_AUTH_ERR;

        if (parse_argv(handle,
                       argc, argv,
                       &flags,
                       &debug) < 0)
                return PAM_AUTH_ERR;

        pam_debug_syslog(handle, debug, "pam-systemd-homed account management");

        r = acquire_home(handle, flags, debug, NULL);
        if (r != PAM_SUCCESS)
                return r;

        r = acquire_user_record(handle, NULL, debug, &ur, NULL);
        if (r != PAM_SUCCESS)
                return r;

        r = user_record_test_blocked(ur);
        switch (r) {

        case -ESTALE:
                pam_syslog(handle, LOG_WARNING, "User record for '%s' is newer than current system time, assuming incorrect system clock, allowing access.", ur->user_name);
                break;

        case -ENOLCK:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("User record is blocked, prohibiting access."));
                return PAM_ACCT_EXPIRED;

        case -EL2HLT:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("User record is not valid yet, prohibiting access."));
                return PAM_ACCT_EXPIRED;

        case -EL3HLT:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("User record is not valid anymore, prohibiting access."));
                return PAM_ACCT_EXPIRED;

        default:
                if (r < 0) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("User record not valid, prohibiting access."));
                        return PAM_ACCT_EXPIRED;
                }

                break;
        }

        t = user_record_ratelimit_next_try(ur);
        if (t != USEC_INFINITY) {
                usec_t n = now(CLOCK_REALTIME);

                if (t > n) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Too many logins, try again in %s."),
                                          FORMAT_TIMESPAN(t - n, USEC_PER_SEC));

                        return PAM_MAXTRIES;
                }
        }

        r = user_record_test_password_change_required(ur);
        switch (r) {

        case -EKEYREVOKED:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password change required."));
                return PAM_NEW_AUTHTOK_REQD;

        case -EOWNERDEAD:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password expired, change required."));
                return PAM_NEW_AUTHTOK_REQD;

        /* Strictly speaking this is only about password expiration, and we might want to allow
         * authentication via PKCS#11 or so, but let's ignore this fine distinction for now. */
        case -EKEYREJECTED:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password is expired, but can't change, refusing login."));
                return PAM_AUTHTOK_EXPIRED;

        case -EKEYEXPIRED:
                (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("Password will expire soon, please change."));
                break;

        case -ESTALE:
                /* If the system clock is wrong, let's log but continue */
                pam_syslog(handle, LOG_WARNING, "Couldn't check if password change is required, last change is in the future, system clock likely wrong.");
                break;

        case -EROFS:
                /* All good, just means the password if we wanted to change we couldn't, but we don't need to */
                break;

        default:
                if (r < 0) {
                        (void) pam_prompt(handle, PAM_ERROR_MSG, NULL, _("User record not valid, prohibiting access."));
                        return PAM_AUTHTOK_EXPIRED;
                }

                break;
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_chauthtok(
                pam_handle_t *handle,
                int sm_flags,
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

        pam_debug_syslog(handle, debug, "pam-systemd-homed account management");

        r = pam_acquire_bus_connection(handle, "pam-systemd-home", &bus, NULL);
        if (r != PAM_SUCCESS)
                return r;

        r = acquire_user_record(handle, NULL, debug, &ur, NULL);
        if (r != PAM_SUCCESS)
                return r;

        /* Start with cached credentials */
        r = pam_get_item_many(
                        handle,
                        PAM_OLDAUTHTOK, &old_password,
                        PAM_AUTHTOK, &new_password);
        if (r != PAM_SUCCESS)
                return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get cached passwords: @PAMERR@");

        if (isempty(new_password)) {
                /* No, it's not cached, then let's ask for the password and its verification, and cache
                 * it. */

                r = pam_get_authtok_noverify(handle, &new_password, "New password: ");
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get new password: @PAMERR@");

                if (isempty(new_password)) {
                        pam_debug_syslog(handle, debug, "Password request aborted.");
                        return PAM_AUTHTOK_ERR;
                }

                r = pam_get_authtok_verify(handle, &new_password, "new password: "); /* Lower case, since PAM prefixes 'Repeat' */
                if (r != PAM_SUCCESS)
                        return pam_syslog_pam_error(handle, LOG_ERR, r, "Failed to get password again: @PAMERR@");

                // FIXME: pam_pwquality will ask for the password a third time. It really shouldn't do
                // that, and instead assume the password was already verified once when it is found to be
                // cached already. needs to be fixed in pam_pwquality
        }

        /* Now everything is cached and checked, let's exit from the preliminary check */
        if (FLAGS_SET(sm_flags, PAM_PRELIM_CHECK))
                return PAM_SUCCESS;

        old_secret = user_record_new();
        if (!old_secret)
                return pam_log_oom(handle);

        if (!isempty(old_password)) {
                r = user_record_set_password(old_secret, STRV_MAKE(old_password), true);
                if (r < 0)
                        return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store old password: %m");
        }

        new_secret = user_record_new();
        if (!new_secret)
                return pam_log_oom(handle);

        r = user_record_set_password(new_secret, STRV_MAKE(new_password), true);
        if (r < 0)
                return pam_syslog_errno(handle, LOG_ERR, r, "Failed to store new password: %m");

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_home_mgr, "ChangePasswordHome");
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
                        r = handle_generic_user_record_error(handle, ur->user_name, old_secret, r, &error, debug);
                        if (r == PAM_CONV_ERR)
                                return pam_syslog_pam_error(handle, LOG_ERR, r,
                                                            "Failed to prompt for password/prompt.");
                        if (r != PAM_SUCCESS)
                                return r;
                } else
                        return pam_syslog_pam_error(handle, LOG_NOTICE, PAM_SUCCESS,
                                                    "Successfully changed password for user %s.", ur->user_name);

                if (++n_attempts >= 5)
                        break;

                /* Try again */
        };

        return pam_syslog_pam_error(handle, LOG_NOTICE, PAM_MAXTRIES,
                                    "Failed to change password for user %s: @PAMERR@", ur->user_name);
}
