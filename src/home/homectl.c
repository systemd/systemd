/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"

#include "ask-password-api.h"
#include "bitfield.h"
#include "build.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "copy.h"
#include "creds-util.h"
#include "dirent-util.h"
#include "dns-domain.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "home-util.h"
#include "homectl-fido2.h"
#include "homectl-pkcs11.h"
#include "homectl-recovery-key.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "password-quality-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "pkcs11-util.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "user-record.h"
#include "user-record-password-quality.h"
#include "user-record-show.h"
#include "user-record-util.h"
#include "user-util.h"
#include "userdb.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_offline = false;
static const char *arg_identity = NULL;
static sd_json_variant *arg_identity_extra = NULL;
static sd_json_variant *arg_identity_extra_privileged = NULL;
static sd_json_variant *arg_identity_extra_this_machine = NULL;
static sd_json_variant *arg_identity_extra_rlimits = NULL;
static char **arg_identity_filter = NULL; /* this one is also applied to 'privileged' and 'thisMachine' subobjects */
static char **arg_identity_filter_rlimits = NULL;
static uint64_t arg_disk_size = UINT64_MAX;
static uint64_t arg_disk_size_relative = UINT64_MAX;
static char **arg_pkcs11_token_uri = NULL;
static char **arg_fido2_device = NULL;
static Fido2EnrollFlags arg_fido2_lock_with = FIDO2ENROLL_PIN | FIDO2ENROLL_UP;
#if HAVE_LIBFIDO2
static int arg_fido2_cred_alg = COSE_ES256;
#else
static int arg_fido2_cred_alg = 0;
#endif
static bool arg_recovery_key = false;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static bool arg_and_resize = false;
static bool arg_and_change_password = false;
static enum {
        EXPORT_FORMAT_FULL,          /* export the full record */
        EXPORT_FORMAT_STRIPPED,      /* strip "state" + "binding", but leave signature in place */
        EXPORT_FORMAT_MINIMAL,       /* also strip signature */
} arg_export_format = EXPORT_FORMAT_FULL;
static uint64_t arg_capability_bounding_set = UINT64_MAX;
static uint64_t arg_capability_ambient_set = UINT64_MAX;
static bool arg_prompt_new_user = false;
static char *arg_blob_dir = NULL;
static bool arg_blob_clear = false;
static Hashmap *arg_blob_files = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_identity_extra, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_this_machine, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_privileged, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_rlimits, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_filter, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_identity_filter_rlimits, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_token_uri, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_device, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_blob_dir, freep);
STATIC_DESTRUCTOR_REGISTER(arg_blob_files, hashmap_freep);

static const BusLocator *bus_mgr;

static bool identity_properties_specified(void) {
        return
                arg_identity ||
                !sd_json_variant_is_blank_object(arg_identity_extra) ||
                !sd_json_variant_is_blank_object(arg_identity_extra_privileged) ||
                !sd_json_variant_is_blank_object(arg_identity_extra_this_machine) ||
                !sd_json_variant_is_blank_object(arg_identity_extra_rlimits) ||
                !strv_isempty(arg_identity_filter) ||
                !strv_isempty(arg_identity_filter_rlimits) ||
                !strv_isempty(arg_pkcs11_token_uri) ||
                !strv_isempty(arg_fido2_device) ||
                arg_blob_dir ||
                arg_blob_clear ||
                !hashmap_isempty(arg_blob_files);
}

static int acquire_bus(sd_bus **bus) {
        int r;

        assert(bus);

        if (*bus)
                return 0;

        r = bus_connect_transport(arg_transport, arg_host, RUNTIME_SCOPE_SYSTEM, bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, RUNTIME_SCOPE_SYSTEM);

        (void) sd_bus_set_allow_interactive_authorization(*bus, arg_ask_password);

        return 0;
}

static int list_homes(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_mgr, "ListHomes", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list homes: %s", bus_error_message(&error, r));

        table = table_new("name", "uid", "gid", "state", "realname", "home", "shell");
        if (!table)
                return log_oom();

        r = sd_bus_message_enter_container(reply, 'a', "(susussso)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *name, *state, *realname, *home, *shell, *color;
                TableCell *cell;
                uint32_t uid, gid;

                r = sd_bus_message_read(reply, "(susussso)", &name, &uid, &state, &gid, &realname, &home, &shell, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = table_add_many(table,
                                   TABLE_STRING, name,
                                   TABLE_UID, uid,
                                   TABLE_GID, gid);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell(table, &cell, TABLE_STRING, state);
                if (r < 0)
                        return table_log_add_error(r);

                color = user_record_state_color(state);
                if (color)
                        (void) table_set_color(table, cell, color);

                r = table_add_many(table,
                                   TABLE_STRING, strna(empty_to_null(realname)),
                                   TABLE_STRING, home,
                                   TABLE_STRING, strna(empty_to_null(shell)));
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (!table_isempty(table) || sd_json_format_enabled(arg_json_format_flags)) {
                r = table_set_sort(table, (size_t) 0);
                if (r < 0)
                        return table_log_sort_error(r);

                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && !sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No home areas.\n");
                else
                        printf("\n%zu home areas listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int acquire_existing_password(
                const char *user_name,
                UserRecord *hr,
                bool emphasize_current,
                AskPasswordFlags flags) {

        _cleanup_strv_free_erase_ char **password = NULL;
        _cleanup_(erase_and_freep) char *envpw = NULL;
        _cleanup_free_ char *question = NULL;
        int r;

        assert(user_name);
        assert(hr);

        r = getenv_steal_erase("PASSWORD", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                /* People really shouldn't use environment variables for passing passwords. We support this
                 * only for testing purposes, and do not document the behaviour, so that people won't
                 * actually use this outside of testing. */

                r = user_record_set_password(hr, STRV_MAKE(envpw), true);
                if (r < 0)
                        return log_error_errno(r, "Failed to store password: %m");

                return 1;
        }

        /* If this is not our own user, then don't use the password cache */
        if (is_this_me(user_name) <= 0)
                SET_FLAG(flags, ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE, false);

        if (asprintf(&question, emphasize_current ?
                     "Please enter current password for user %s:" :
                     "Please enter password for user %s:",
                     user_name) < 0)
                return log_oom();

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = question,
                .icon = "user-home",
                .keyring = "home-password",
                .credential = "home.password",
                .until = USEC_INFINITY,
                .hup_fd = -EBADF,
        };

        r = ask_password_auto(&req, flags, &password);
        if (r == -EUNATCH) { /* EUNATCH is returned if no password was found and asking interactively was
                              * disabled via the flags. Not an error for us. */
                log_debug_errno(r, "No passwords acquired.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password: %m");

        r = user_record_set_password(hr, password, true);
        if (r < 0)
                return log_error_errno(r, "Failed to store password: %m");

        return 1;
}

static int acquire_recovery_key(
                const char *user_name,
                UserRecord *hr,
                AskPasswordFlags flags) {

        _cleanup_strv_free_erase_ char **recovery_key = NULL;
        _cleanup_(erase_and_freep) char *envpw = NULL;
        _cleanup_free_ char *question = NULL;
        int r;

        assert(user_name);
        assert(hr);

        r = getenv_steal_erase("PASSWORD", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                /* People really shouldn't use environment variables for passing secrets. We support this
                 * only for testing purposes, and do not document the behaviour, so that people won't
                 * actually use this outside of testing. */

                r = user_record_set_password(hr, STRV_MAKE(envpw), true); /* recovery keys are stored in the record exactly like regular passwords! */
                if (r < 0)
                        return log_error_errno(r, "Failed to store recovery key: %m");

                return 1;
        }

        /* If this is not our own user, then don't use the password cache */
        if (is_this_me(user_name) <= 0)
                SET_FLAG(flags, ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE, false);

        if (asprintf(&question, "Please enter recovery key for user %s:", user_name) < 0)
                return log_oom();

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = question,
                .icon = "user-home",
                .keyring = "home-recovery-key",
                .credential = "home.recovery-key",
                .until = USEC_INFINITY,
                .hup_fd = -EBADF,
        };

        r = ask_password_auto(&req, flags, &recovery_key);
        if (r == -EUNATCH) { /* EUNATCH is returned if no recovery key was found and asking interactively was
                              * disabled via the flags. Not an error for us. */
                log_debug_errno(r, "No recovery keys acquired.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire recovery keys: %m");

        r = user_record_set_password(hr, recovery_key, true);
        if (r < 0)
                return log_error_errno(r, "Failed to store recovery keys: %m");

        return 1;
}

static int acquire_token_pin(
                const char *user_name,
                UserRecord *hr,
                AskPasswordFlags flags) {

        _cleanup_strv_free_erase_ char **pin = NULL;
        _cleanup_(erase_and_freep) char *envpin = NULL;
        _cleanup_free_ char *question = NULL;
        int r;

        assert(user_name);
        assert(hr);

        r = getenv_steal_erase("PIN", &envpin);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire PIN from environment: %m");
        if (r > 0) {
                r = user_record_set_token_pin(hr, STRV_MAKE(envpin), false);
                if (r < 0)
                        return log_error_errno(r, "Failed to store token PIN: %m");

                return 1;
        }

        /* If this is not our own user, then don't use the password cache */
        if (is_this_me(user_name) <= 0)
                SET_FLAG(flags, ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE, false);

        if (asprintf(&question, "Please enter security token PIN for user %s:", user_name) < 0)
                return log_oom();

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = question,
                .icon = "user-home",
                .keyring = "token-pin",
                .credential = "home.token-pin",
                .until = USEC_INFINITY,
                .hup_fd = -EBADF,
        };

        r = ask_password_auto(&req, flags, &pin);
        if (r == -EUNATCH) { /* EUNATCH is returned if no PIN was found and asking interactively was disabled
                              * via the flags. Not an error for us. */
                log_debug_errno(r, "No security token PINs acquired.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire security token PIN: %m");

        r = user_record_set_token_pin(hr, pin, false);
        if (r < 0)
                return log_error_errno(r, "Failed to store security token PIN: %m");

        return 1;
}

static int handle_generic_user_record_error(
                const char *user_name,
                UserRecord *hr,
                const sd_bus_error *error,
                int ret,
                bool emphasize_current_password) {
        int r;

        assert(user_name);
        assert(hr);

        if (sd_bus_error_has_name(error, BUS_ERROR_HOME_ABSENT))
                return log_error_errno(SYNTHETIC_ERRNO(EREMOTE),
                                       "Home of user %s is currently absent, please plug in the necessary storage device or backing file system.", user_name);

        else if (sd_bus_error_has_name(error, BUS_ERROR_AUTHENTICATION_LIMIT_HIT))
                return log_error_errno(SYNTHETIC_ERRNO(ETOOMANYREFS),
                                       "Too frequent login attempts for user %s, try again later.", user_name);

        else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_PASSWORD)) {

                if (!strv_isempty(hr->password))
                        log_notice("Password incorrect or not sufficient, please try again.");

                /* Don't consume cache entries or credentials here, we already tried that unsuccessfully. But
                 * let's push what we acquire here into the cache */
                r = acquire_existing_password(
                                user_name,
                                hr,
                                emphasize_current_password,
                                ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_NO_CREDENTIAL);
                if (r < 0)
                        return r;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_RECOVERY_KEY)) {

                if (!strv_isempty(hr->password))
                        log_notice("Recovery key incorrect or not sufficient, please try again.");

                /* Don't consume cache entries or credentials here, we already tried that unsuccessfully. But
                 * let's push what we acquire here into the cache */
                r = acquire_recovery_key(
                                user_name,
                                hr,
                                ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_NO_CREDENTIAL);
                if (r < 0)
                        return r;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN)) {

                if (strv_isempty(hr->password))
                        log_notice("Security token not inserted, please enter password.");
                else
                        log_notice("Password incorrect or not sufficient, and configured security token not inserted, please try again.");

                r = acquire_existing_password(
                                user_name,
                                hr,
                                emphasize_current_password,
                                ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_NO_CREDENTIAL);
                if (r < 0)
                        return r;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PIN_NEEDED)) {

                /* First time the PIN is requested, let's accept cached data, and allow using credential store */
                r = acquire_token_pin(
                                user_name,
                                hr,
                                ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_PUSH_CACHE);
                if (r < 0)
                        return r;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PROTECTED_AUTHENTICATION_PATH_NEEDED)) {

                log_notice("%s%sPlease authenticate physically on security token.",
                           emoji_enabled() ? special_glyph(SPECIAL_GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

                r = user_record_set_pkcs11_protected_authentication_path_permitted(hr, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to set PKCS#11 protected authentication path permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_USER_PRESENCE_NEEDED)) {

                log_notice("%s%sPlease confirm presence on security token.",
                           emoji_enabled() ? special_glyph(SPECIAL_GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

                r = user_record_set_fido2_user_presence_permitted(hr, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to set FIDO2 user presence permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_USER_VERIFICATION_NEEDED)) {

                log_notice("%s%sPlease verify user on security token.",
                           emoji_enabled() ? special_glyph(SPECIAL_GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

                r = user_record_set_fido2_user_verification_permitted(hr, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to set FIDO2 user verification permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_PIN_LOCKED))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Security token PIN is locked, please unlock it first. (Hint: Removal and re-insertion might suffice.)");

        else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN)) {

                log_notice("Security token PIN incorrect, please try again.");

                /* If the previous PIN was wrong don't accept cached info anymore, but add to cache. Also, don't use the credential data */
                r = acquire_token_pin(
                                user_name,
                                hr,
                                ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_NO_CREDENTIAL);
                if (r < 0)
                        return r;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN_FEW_TRIES_LEFT)) {

                log_notice("Security token PIN incorrect, please try again (only a few tries left!).");

                r = acquire_token_pin(
                                user_name,
                                hr,
                                ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_NO_CREDENTIAL);
                if (r < 0)
                        return r;

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_BAD_PIN_ONE_TRY_LEFT)) {

                log_notice("Security token PIN incorrect, please try again (only one try left!).");

                r = acquire_token_pin(
                                user_name,
                                hr,
                                ASK_PASSWORD_PUSH_CACHE | ASK_PASSWORD_NO_CREDENTIAL);
                if (r < 0)
                        return r;
        } else
                return log_error_errno(ret, "Operation on home %s failed: %s", user_name, bus_error_message(error, ret));

        return 0;
}

static int acquire_passed_secrets(const char *user_name, UserRecord **ret) {
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        int r;

        assert(ret);

        /* Generates an initial secret objects that contains passwords supplied via $PASSWORD, the password
         * cache or the credentials subsystem, but excluding any interactive stuff. If nothing is passed,
         * returns an empty secret object. */

        secret = user_record_new();
        if (!secret)
                return log_oom();

        r = acquire_existing_password(
                        user_name,
                        secret,
                        /* emphasize_current_password = */ false,
                        ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_NO_TTY | ASK_PASSWORD_NO_AGENT);
        if (r < 0)
                return r;

        r = acquire_token_pin(
                        user_name,
                        secret,
                        ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_NO_TTY | ASK_PASSWORD_NO_AGENT);
        if (r < 0)
                return r;

        r = acquire_recovery_key(
                        user_name,
                        secret,
                        ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_NO_TTY | ASK_PASSWORD_NO_AGENT);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(secret);
        return 0;
}

static int activate_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(user_record_unrefp) UserRecord *secret = NULL;

                r = acquire_passed_secrets(*i, &secret);
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = bus_message_new_method_call(bus, &m, bus_mgr, "ActivateHome");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", *i);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                r = handle_generic_user_record_error(*i, secret, &error, r, /* emphasize_current_password= */ false);
                                if (r < 0) {
                                        if (ret == 0)
                                                ret = r;

                                        break;
                                }
                        } else
                                break;
                }
        }

        return ret;
}

static int deactivate_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "DeactivateHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to deactivate user home: %s", bus_error_message(&error, r));
                        if (ret == 0)
                                ret = r;
                }
        }

        return ret;
}

static void dump_home_record(UserRecord *hr) {
        int r;

        assert(hr);

        if (hr->incomplete) {
                fflush(stdout);
                log_warning("Warning: lacking rights to acquire privileged fields of user record of '%s', output incomplete.", hr->user_name);
        }

        if (!sd_json_format_enabled(arg_json_format_flags))
                user_record_show(hr, true);
        else {
                _cleanup_(user_record_unrefp) UserRecord *stripped = NULL;

                if (arg_export_format == EXPORT_FORMAT_STRIPPED)
                        r = user_record_clone(hr, USER_RECORD_EXTRACT_EMBEDDED|USER_RECORD_PERMISSIVE, &stripped);
                else if (arg_export_format == EXPORT_FORMAT_MINIMAL)
                        r = user_record_clone(hr, USER_RECORD_EXTRACT_SIGNABLE|USER_RECORD_PERMISSIVE, &stripped);
                else
                        r = 0;
                if (r < 0)
                        log_warning_errno(r, "Failed to strip user record, ignoring: %m");
                if (stripped)
                        hr = stripped;

                sd_json_variant_dump(hr->json, arg_json_format_flags, stdout, NULL);
        }
}

static char **mangle_user_list(char **list, char ***ret_allocated) {
        _cleanup_free_ char *myself = NULL;
        char **l;

        if (!strv_isempty(list)) {
                *ret_allocated = NULL;
                return list;
        }

        myself = getusername_malloc();
        if (!myself)
                return NULL;

        l = new(char*, 2);
        if (!l)
                return NULL;

        l[0] = TAKE_PTR(myself);
        l[1] = NULL;

        *ret_allocated = l;
        return l;
}

static int inspect_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **mangled_list = NULL;
        int r, ret = 0;
        char **items;

        pager_open(arg_pager_flags);

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        items = mangle_user_list(strv_skip(argv, 1), &mangled_list);
        if (!items)
                return log_oom();

        STRV_FOREACH(i, items) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
                const char *json;
                int incomplete;
                uid_t uid;

                r = parse_uid(*i, &uid);
                if (r < 0)
                        r = bus_call_method(bus, bus_mgr, "GetUserRecordByName", &error, &reply, "s", *i);
                else
                        r = bus_call_method(bus, bus_mgr, "GetUserRecordByUID", &error, &reply, "u", (uint32_t) uid);
                if (r < 0) {
                        log_error_errno(r, "Failed to inspect home: %s", bus_error_message(&error, r));
                        if (ret == 0)
                                ret = r;

                        continue;
                }

                r = sd_bus_message_read(reply, "sbo", &json, &incomplete, NULL);
                if (r < 0) {
                        bus_log_parse_error(r);
                        if (ret == 0)
                                ret = r;

                        continue;
                }

                r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse JSON identity: %m");
                        if (ret == 0)
                                ret = r;

                        continue;
                }

                hr = user_record_new();
                if (!hr)
                        return log_oom();

                r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_LOG|USER_RECORD_PERMISSIVE);
                if (r < 0) {
                        if (ret == 0)
                                ret = r;

                        continue;
                }

                hr->incomplete = incomplete;
                dump_home_record(hr);
        }

        return ret;
}

static int authenticate_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **mangled_list = NULL;
        int r, ret = 0;
        char **items;

        items = mangle_user_list(strv_skip(argv, 1), &mangled_list);
        if (!items)
                return log_oom();

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        STRV_FOREACH(i, items) {
                _cleanup_(user_record_unrefp) UserRecord *secret = NULL;

                r = acquire_passed_secrets(*i, &secret);
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = bus_message_new_method_call(bus, &m, bus_mgr, "AuthenticateHome");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", *i);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                r = handle_generic_user_record_error(*i, secret, &error, r, false);
                                if (r < 0) {
                                        if (ret == 0)
                                                ret = r;

                                        break;
                                }
                        } else
                                break;
                }
        }

        return ret;
}

static int update_last_change(sd_json_variant **v, bool with_password, bool override) {
        sd_json_variant *c;
        usec_t n;
        int r;

        assert(v);

        n = now(CLOCK_REALTIME);

        c = sd_json_variant_by_key(*v, "lastChangeUSec");
        if (c) {
                uint64_t u;

                if (!override)
                        goto update_password;

                if (!sd_json_variant_is_unsigned(c))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "lastChangeUSec field is not an unsigned integer, refusing.");

                u = sd_json_variant_unsigned(c);
                if (u >= n)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "lastChangeUSec is from the future, can't update.");
        }

        r = sd_json_variant_set_field_unsigned(v, "lastChangeUSec", n);
        if (r < 0)
                return log_error_errno(r, "Failed to update lastChangeUSec: %m");

update_password:
        if (!with_password)
                return 0;

        c = sd_json_variant_by_key(*v, "lastPasswordChangeUSec");
        if (c) {
                uint64_t u;

                if (!override)
                        return 0;

                if (!sd_json_variant_is_unsigned(c))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "lastPasswordChangeUSec field is not an unsigned integer, refusing.");

                u = sd_json_variant_unsigned(c);
                if (u >= n)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "lastPasswordChangeUSec is from the future, can't update.");
        }

        r = sd_json_variant_set_field_unsigned(v, "lastPasswordChangeUSec", n);
        if (r < 0)
                return log_error_errno(r, "Failed to update lastPasswordChangeUSec: %m");

        return 1;
}

static int apply_identity_changes(sd_json_variant **_v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(_v);

        v = sd_json_variant_ref(*_v);

        r = sd_json_variant_filter(&v, arg_identity_filter);
        if (r < 0)
                return log_error_errno(r, "Failed to filter identity: %m");

        r = sd_json_variant_merge_object(&v, arg_identity_extra);
        if (r < 0)
                return log_error_errno(r, "Failed to merge identities: %m");

        if (arg_identity_extra_this_machine || !strv_isempty(arg_identity_filter)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *per_machine = NULL, *mmid = NULL;
                sd_id128_t mid;

                r = sd_id128_get_machine(&mid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire machine ID: %m");

                r = sd_json_variant_new_string(&mmid, SD_ID128_TO_STRING(mid));
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate matchMachineId object: %m");

                per_machine = sd_json_variant_ref(sd_json_variant_by_key(v, "perMachine"));
                if (per_machine) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *npm = NULL, *add = NULL;
                        _cleanup_free_ sd_json_variant **array = NULL;
                        sd_json_variant *z;
                        size_t i = 0;

                        if (!sd_json_variant_is_array(per_machine))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "perMachine field is not an array, refusing.");

                        array = new(sd_json_variant*, sd_json_variant_elements(per_machine) + 1);
                        if (!array)
                                return log_oom();

                        JSON_VARIANT_ARRAY_FOREACH(z, per_machine) {
                                sd_json_variant *u;

                                if (!sd_json_variant_is_object(z))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "perMachine entry is not an object, refusing.");

                                array[i++] = z;

                                u = sd_json_variant_by_key(z, "matchMachineId");
                                if (!u)
                                        continue;

                                if (!sd_json_variant_equal(u, mmid))
                                        continue;

                                r = sd_json_variant_merge_object(&add, z);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to merge perMachine entry: %m");

                                i--;
                        }

                        r = sd_json_variant_filter(&add, arg_identity_filter);
                        if (r < 0)
                                return log_error_errno(r, "Failed to filter perMachine: %m");

                        r = sd_json_variant_merge_object(&add, arg_identity_extra_this_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to merge in perMachine fields: %m");

                        if (arg_identity_filter_rlimits || arg_identity_extra_rlimits) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *rlv = NULL;

                                rlv = sd_json_variant_ref(sd_json_variant_by_key(add, "resourceLimits"));

                                r = sd_json_variant_filter(&rlv, arg_identity_filter_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to filter resource limits: %m");

                                r = sd_json_variant_merge_object(&rlv, arg_identity_extra_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set resource limits: %m");

                                if (sd_json_variant_is_blank_object(rlv)) {
                                        r = sd_json_variant_filter(&add, STRV_MAKE("resourceLimits"));
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to drop resource limits field from identity: %m");
                                } else {
                                        r = sd_json_variant_set_field(&add, "resourceLimits", rlv);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to update resource limits of identity: %m");
                                }
                        }

                        if (!sd_json_variant_is_blank_object(add)) {
                                r = sd_json_variant_set_field(&add, "matchMachineId", mmid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set matchMachineId field: %m");

                                array[i++] = add;
                        }

                        r = sd_json_variant_new_array(&npm, array, i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate new perMachine array: %m");

                        sd_json_variant_unref(per_machine);
                        per_machine = TAKE_PTR(npm);
                } else {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *item = sd_json_variant_ref(arg_identity_extra_this_machine);

                        if (arg_identity_extra_rlimits) {
                                r = sd_json_variant_set_field(&item, "resourceLimits", arg_identity_extra_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update resource limits of identity: %m");
                        }

                        r = sd_json_variant_set_field(&item, "matchMachineId", mmid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set matchMachineId field: %m");

                        r = sd_json_variant_append_array(&per_machine, item);
                        if (r < 0)
                                return log_error_errno(r, "Failed to append to perMachine array: %m");
                }

                r = sd_json_variant_set_field(&v, "perMachine", per_machine);
                if (r < 0)
                        return log_error_errno(r, "Failed to update per machine record: %m");
        }

        if (arg_identity_extra_privileged || arg_identity_filter) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *privileged = NULL;

                privileged = sd_json_variant_ref(sd_json_variant_by_key(v, "privileged"));

                r = sd_json_variant_filter(&privileged, arg_identity_filter);
                if (r < 0)
                        return log_error_errno(r, "Failed to filter identity (privileged part): %m");

                r = sd_json_variant_merge_object(&privileged, arg_identity_extra_privileged);
                if (r < 0)
                        return log_error_errno(r, "Failed to merge identities (privileged part): %m");

                if (sd_json_variant_is_blank_object(privileged)) {
                        r = sd_json_variant_filter(&v, STRV_MAKE("privileged"));
                        if (r < 0)
                                return log_error_errno(r, "Failed to drop privileged part from identity: %m");
                } else {
                        r = sd_json_variant_set_field(&v, "privileged", privileged);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update privileged part of identity: %m");
                }
        }

        if (arg_identity_filter_rlimits) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *rlv = NULL;

                rlv = sd_json_variant_ref(sd_json_variant_by_key(v, "resourceLimits"));

                r = sd_json_variant_filter(&rlv, arg_identity_filter_rlimits);
                if (r < 0)
                        return log_error_errno(r, "Failed to filter resource limits: %m");

                /* Note that we only filter resource limits here, but don't apply them. We do that in the perMachine section */

                if (sd_json_variant_is_blank_object(rlv)) {
                        r = sd_json_variant_filter(&v, STRV_MAKE("resourceLimits"));
                        if (r < 0)
                                return log_error_errno(r, "Failed to drop resource limits field from identity: %m");
                } else {
                        r = sd_json_variant_set_field(&v, "resourceLimits", rlv);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update resource limits of identity: %m");
                }
        }

        sd_json_variant_unref(*_v);
        *_v = TAKE_PTR(v);

        return 0;
}

static int add_disposition(sd_json_variant **v) {
        int r;

        assert(v);

        if (sd_json_variant_by_key(*v, "disposition"))
                return 0;

        /* Set the disposition to regular, if not configured explicitly */
        r = sd_json_variant_set_field_string(v, "disposition", "regular");
        if (r < 0)
                return log_error_errno(r, "Failed to set disposition field: %m");

        return 1;
}

static int acquire_new_home_record(sd_json_variant *input, UserRecord **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        assert(ret);

        if (arg_identity) {
                unsigned line, column;

                if (input)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Two identity records specified, refusing.");

                r = sd_json_parse_file(
                                streq(arg_identity, "-") ? stdin : NULL,
                                streq(arg_identity, "-") ? "<stdin>" : arg_identity, SD_JSON_PARSE_SENSITIVE, &v, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse identity at %u:%u: %m", line, column);
        } else
                v = sd_json_variant_ref(input);

        r = apply_identity_changes(&v);
        if (r < 0)
                return r;

        r = add_disposition(&v);
        if (r < 0)
                return r;

        STRV_FOREACH(i, arg_pkcs11_token_uri) {
                r = identity_add_pkcs11_key_data(&v, *i);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, arg_fido2_device) {
                r = identity_add_fido2_parameters(&v, *i, arg_fido2_lock_with, arg_fido2_cred_alg);
                if (r < 0)
                        return r;
        }

        if (arg_recovery_key) {
                r = identity_add_recovery_key(&v);
                if (r < 0)
                        return r;
        }

        r = update_last_change(&v, true, false);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING)
                sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY, NULL, NULL);

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(
                        hr,
                        v,
                        USER_RECORD_REQUIRE_REGULAR|
                        USER_RECORD_ALLOW_SECRET|
                        USER_RECORD_ALLOW_PRIVILEGED|
                        USER_RECORD_ALLOW_PER_MACHINE|
                        USER_RECORD_STRIP_BINDING|
                        USER_RECORD_STRIP_STATUS|
                        USER_RECORD_STRIP_SIGNATURE|
                        USER_RECORD_LOG|
                        USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(hr);
        return 0;
}

static int acquire_new_password(
                const char *user_name,
                UserRecord *hr,
                bool suggest,
                char **ret) {

        _cleanup_(erase_and_freep) char *envpw = NULL;
        unsigned i = 5;
        int r;

        assert(user_name);
        assert(hr);

        r = getenv_steal_erase("NEWPASSWORD", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                /* As above, this is not for use, just for testing */

                r = user_record_set_password(hr, STRV_MAKE(envpw), /* prepend = */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to store password: %m");

                if (ret)
                        *ret = TAKE_PTR(envpw);

                return 0;
        }

        if (suggest)
                (void) suggest_passwords();

        for (;;) {
                _cleanup_strv_free_erase_ char **first = NULL, **second = NULL;
                _cleanup_free_ char *question = NULL;

                if (--i == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Too many attempts, giving up.");

                if (asprintf(&question, "Please enter new password for user %s:", user_name) < 0)
                        return log_oom();

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = question,
                        .icon = "user-home",
                        .keyring = "home-password",
                        .credential = "home.new-password",
                        .until = USEC_INFINITY,
                        .hup_fd = -EBADF,
                };

                r = ask_password_auto(
                                &req,
                                /* flags= */ 0, /* no caching, we want to collect a new password here after all */
                                &first);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire password: %m");

                assert(!strv_isempty(first));

                question = mfree(question);
                if (asprintf(&question, "Please enter new password for user %s (repeat):", user_name) < 0)
                        return log_oom();

                req.message = question;

                r = ask_password_auto(
                                &req,
                                /* flags= */ 0, /* no caching */
                                &second);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire password: %m");

                if (strv_equal(first, second)) {
                        _cleanup_(erase_and_freep) char *copy = NULL;

                        if (ret) {
                                copy = strdup(first[0]);
                                if (!copy)
                                        return log_oom();
                        }

                        r = user_record_set_password(hr, first, /* prepend = */ true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to store password: %m");

                        if (ret)
                                *ret = TAKE_PTR(copy);

                        return 0;
                }

                log_error("Password didn't match, try again.");
        }
}

static int acquire_merged_blob_dir(UserRecord *hr, bool existing, Hashmap **ret) {
        _cleanup_free_ char *sys_blob_path = NULL;
        _cleanup_hashmap_free_ Hashmap *blobs = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *src_blob_path, *filename;
        void *fd_ptr;
        int r;

        assert(ret);

        HASHMAP_FOREACH_KEY(fd_ptr, filename, arg_blob_files) {
                _cleanup_free_ char *filename_dup = NULL;
                _cleanup_close_ int fd_dup = -EBADF;

                filename_dup = strdup(filename);
                if (!filename_dup)
                        return log_oom();

                if (PTR_TO_FD(fd_ptr) != -EBADF) {
                        fd_dup = fcntl(PTR_TO_FD(fd_ptr), F_DUPFD_CLOEXEC, 3);
                        if (fd_dup < 0)
                                return log_error_errno(errno, "Failed to duplicate fd of %s: %m", filename);
                }

                r = hashmap_ensure_put(&blobs, &blob_fd_hash_ops, filename_dup, FD_TO_PTR(fd_dup));
                if (r < 0)
                        return r;
                TAKE_PTR(filename_dup); /* Ownership transferred to hashmap */
                TAKE_FD(fd_dup);
        }

        if (arg_blob_dir)
                src_blob_path = arg_blob_dir;
        else if (existing && !arg_blob_clear) {
                if (hr->blob_directory)
                        src_blob_path = hr->blob_directory;
                else {
                        /* This isn't technically a correct thing to do for generic user records,
                         * so anyone looking at this code for reference shouldn't replicate it.
                         * However, since homectl is tied to homed, this is OK. This adds robustness
                         * for situations where the user record is coming directly from the CLI and
                         * thus doesn't have a blobDirectory set */

                        sys_blob_path = path_join(home_system_blob_dir(), hr->user_name);
                        if (!sys_blob_path)
                                return log_oom();

                        src_blob_path = sys_blob_path;
                }
        } else
                goto nodir; /* Shortcut: no dir to merge with, so just return copy of arg_blob_files */

        d = opendir(src_blob_path);
        if (!d)
                return log_error_errno(errno, "Failed to open %s: %m", src_blob_path);

        FOREACH_DIRENT_ALL(de, d, return log_error_errno(errno, "Failed to read %s: %m", src_blob_path)) {
                _cleanup_free_ char *name = NULL;
                _cleanup_close_ int fd = -EBADF;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (hashmap_contains(blobs, de->d_name))
                        continue; /* arg_blob_files should override the base dir */

                if (!suitable_blob_filename(de->d_name)) {
                        log_warning("File %s in blob directory %s has an invalid filename. Skipping.", de->d_name, src_blob_path);
                        continue;
                }

                name = strdup(de->d_name);
                if (!name)
                        return log_oom();

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s in %s: %m", de->d_name, src_blob_path);

                r = fd_verify_regular(fd);
                if (r < 0) {
                        log_warning_errno(r, "Entry %s in blob directory %s is not a regular file. Skipping.", de->d_name, src_blob_path);
                        continue;
                }

                r = hashmap_ensure_put(&blobs, &blob_fd_hash_ops, name, FD_TO_PTR(fd));
                if (r < 0)
                        return r;
                TAKE_PTR(name); /* Ownership transferred to hashmap */
                TAKE_FD(fd);
        }

nodir:
        *ret = TAKE_PTR(blobs);
        return 0;
}

static int bus_message_append_blobs(sd_bus_message *m, Hashmap *blobs) {
        const char *filename;
        void *fd_ptr;
        int r;

        assert(m);

        r = sd_bus_message_open_container(m, 'a', "{sh}");
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(fd_ptr, filename, blobs) {
                int fd = PTR_TO_FD(fd_ptr);

                if (fd == -EBADF) /* File marked for deletion */
                        continue;

                r = sd_bus_message_append(m, "{sh}", filename, fd);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(m);
}

static int create_home_common(sd_json_variant *input) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        _cleanup_hashmap_free_ Hashmap *blobs = NULL;
        int r;

        r = acquire_new_home_record(input, &hr);
        if (r < 0)
                return r;

        r = acquire_merged_blob_dir(hr, false, &blobs);
        if (r < 0)
                return r;

        /* If the JSON record carries no plain text password (besides the recovery key), then let's query it
         * manually. */
        if (strv_length(hr->password) <= arg_recovery_key) {

                if (strv_isempty(hr->hashed_password)) {
                        _cleanup_(erase_and_freep) char *new_password = NULL;

                        /* No regular (i.e. non-PKCS#11) hashed passwords set in the record, let's fix that. */
                        r = acquire_new_password(hr->user_name, hr, /* suggest = */ true, &new_password);
                        if (r < 0)
                                return r;

                        r = user_record_make_hashed_password(hr, STRV_MAKE(new_password), /* extend = */ false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to hash password: %m");
                } else {
                        /* There's a hash password set in the record, acquire the unhashed version of it. */
                        r = acquire_existing_password(
                                        hr->user_name,
                                        hr,
                                        /* emphasize_current= */ false,
                                        ASK_PASSWORD_ACCEPT_CACHED | ASK_PASSWORD_PUSH_CACHE);
                        if (r < 0)
                                return r;
                }
        }

        if (hr->enforce_password_policy == 0) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                /* If password quality enforcement is disabled, let's at least warn client side */

                r = user_record_check_password_quality(hr, hr, &error);
                if (r < 0)
                        log_warning_errno(r, "Specified password does not pass quality checks (%s), proceeding anyway.", bus_error_message(&error, r));
        }

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_(erase_and_freep) char *formatted = NULL;

                r = sd_json_variant_format(hr->json, 0, &formatted);
                if (r < 0)
                        return log_error_errno(r, "Failed to format user record: %m");

                r = bus_message_new_method_call(bus, &m, bus_mgr, "CreateHomeEx");
                if (r < 0)
                        return bus_log_create_error(r);

                (void) sd_bus_message_sensitive(m);

                r = sd_bus_message_append(m, "s", formatted);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_blobs(m, blobs);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "t", UINT64_C(0));
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (sd_bus_error_has_name(&error, BUS_ERROR_LOW_PASSWORD_QUALITY)) {
                                _cleanup_(erase_and_freep) char *new_password = NULL;

                                log_error_errno(r, "%s", bus_error_message(&error, r));
                                log_info("(Use --enforce-password-policy=no to turn off password quality checks for this account.)");

                                r = acquire_new_password(hr->user_name, hr, /* suggest = */ false, &new_password);
                                if (r < 0)
                                        return r;

                                r = user_record_make_hashed_password(hr, STRV_MAKE(new_password), /* extend = */ false);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to hash passwords: %m");
                        } else {
                                r = handle_generic_user_record_error(hr->user_name, hr, &error, r, false);
                                if (r < 0)
                                        return r;
                        }
                } else
                        break; /* done */
        }

        return 0;
}

static int create_home(int argc, char *argv[], void *userdata) {
        int r;

        if (argc >= 2) {
                /* If a username was specified, use it */

                if (valid_user_group_name(argv[1], 0))
                        r = sd_json_variant_set_field_string(&arg_identity_extra, "userName", argv[1]);
                else {
                        _cleanup_free_ char *un = NULL, *rr = NULL;

                        /* Before we consider the user name invalid, let's check if we can split it? */
                        r = split_user_name_realm(argv[1], &un, &rr);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User name '%s' is not valid.", argv[1]);

                        if (rr) {
                                r = sd_json_variant_set_field_string(&arg_identity_extra, "realm", rr);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set realm field: %m");
                        }

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "userName", un);
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to set userName field: %m");
        } else {
                /* If neither a username nor an identity have been specified we cannot operate. */
                if (!arg_identity)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User name required.");
        }

        return create_home_common(/* input= */ NULL);
}

static int remove_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "RemoveHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to remove home: %s", bus_error_message(&error, r));
                        if (ret == 0)
                                ret = r;
                }
        }

        return ret;
}

static int acquire_updated_home_record(
                sd_bus *bus,
                const char *username,
                UserRecord **ret) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        assert(ret);

        if (arg_identity) {
                unsigned line, column;
                sd_json_variant *un;

                r = sd_json_parse_file(
                                streq(arg_identity, "-") ? stdin : NULL,
                                streq(arg_identity, "-") ? "<stdin>" : arg_identity, SD_JSON_PARSE_SENSITIVE, &json, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse identity at %u:%u: %m", line, column);

                un = sd_json_variant_by_key(json, "userName");
                if (un) {
                        if (!sd_json_variant_is_string(un) || (username && !streq(sd_json_variant_string(un), username)))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User name specified on command line and in JSON record do not match.");
                } else {
                        if (!username)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No username specified.");

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "userName", username);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set userName field: %m");
                }

        } else {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                int incomplete;
                const char *text;

                if (!identity_properties_specified())
                        return log_error_errno(SYNTHETIC_ERRNO(EALREADY), "No field to change specified.");

                r = bus_call_method(bus, bus_mgr, "GetUserRecordByName", &error, &reply, "s", username);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire user home record: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "sbo", &text, &incomplete, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (incomplete)
                        return log_error_errno(SYNTHETIC_ERRNO(EACCES), "Lacking rights to acquire user record including privileged metadata, can't update record.");

                r = sd_json_parse(text, SD_JSON_PARSE_SENSITIVE, &json, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON identity: %m");

                reply = sd_bus_message_unref(reply);

                r = sd_json_variant_filter(&json, STRV_MAKE("binding", "status", "signature", "blobManifest"));
                if (r < 0)
                        return log_error_errno(r, "Failed to strip binding and status from record to update: %m");
        }

        r = apply_identity_changes(&json);
        if (r < 0)
                return r;

        STRV_FOREACH(i, arg_pkcs11_token_uri) {
                r = identity_add_pkcs11_key_data(&json, *i);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, arg_fido2_device) {
                r = identity_add_fido2_parameters(&json, *i, arg_fido2_lock_with, arg_fido2_cred_alg);
                if (r < 0)
                        return r;
        }

        /* If the user supplied a full record, then add in lastChange, but do not override. Otherwise always
         * override. */
        r = update_last_change(&json, arg_pkcs11_token_uri || arg_fido2_device, !arg_identity);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING)
                sd_json_variant_dump(json, SD_JSON_FORMAT_PRETTY, NULL, NULL);

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(hr, json, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_SECRET|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_LOG|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(hr);
        return 0;
}

static int home_record_reset_human_interaction_permission(UserRecord *hr) {
        int r;

        assert(hr);

        /* When we execute multiple operations one after the other, let's reset the permission to ask the
         * user each time, so that if interaction is necessary we will be told so again and thus can print a
         * nice message to the user, telling the user so. */

        r = user_record_set_pkcs11_protected_authentication_path_permitted(hr, -1);
        if (r < 0)
                return log_error_errno(r, "Failed to reset PKCS#11 protected authentication path permission flag: %m");

        r = user_record_set_fido2_user_presence_permitted(hr, -1);
        if (r < 0)
                return log_error_errno(r, "Failed to reset FIDO2 user presence permission flag: %m");

        r = user_record_set_fido2_user_verification_permitted(hr, -1);
        if (r < 0)
                return log_error_errno(r, "Failed to reset FIDO2 user verification permission flag: %m");

        return 0;
}

static int update_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL, *secret = NULL;
        _cleanup_free_ char *buffer = NULL;
        _cleanup_hashmap_free_ Hashmap *blobs = NULL;
        const char *username;
        uint64_t flags = 0;
        int r;

        if (argc >= 2)
                username = argv[1];
        else if (!arg_identity) {
                buffer = getusername_malloc();
                if (!buffer)
                        return log_oom();

                username = buffer;
        } else
                username = NULL;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = acquire_updated_home_record(bus, username, &hr);
        if (r < 0)
                return r;

        /* Add in all secrets we can acquire cheaply */
        r = acquire_passed_secrets(username, &secret);
        if (r < 0)
                return r;

        r = user_record_merge_secret(hr, secret);
        if (r < 0)
                return r;

        r = acquire_merged_blob_dir(hr, true, &blobs);
        if (r < 0)
                return r;

        /* If we do multiple operations, let's output things more verbosely, since otherwise the repeated
         * authentication might be confusing. */

        if (arg_and_resize || arg_and_change_password)
                log_info("Updating home directory.");

        if (arg_offline)
                flags |= SD_HOMED_UPDATE_OFFLINE;

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_free_ char *formatted = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "UpdateHomeEx");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_json_variant_format(hr->json, 0, &formatted);
                if (r < 0)
                        return log_error_errno(r, "Failed to format user record: %m");

                (void) sd_bus_message_sensitive(m);

                r = sd_bus_message_append(m, "s", formatted);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_blobs(m, blobs);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "t", flags);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (arg_and_change_password &&
                            sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN))
                                /* In the generic handler we'd ask for a password in this case, but when
                                 * changing passwords that's not sufficient, as we need to acquire all keys
                                 * first. */
                                return log_error_errno(r, "Security token not inserted, refusing.");

                        r = handle_generic_user_record_error(hr->user_name, hr, &error, r, false);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        if (arg_and_resize)
                log_info("Resizing home.");

        (void) home_record_reset_human_interaction_permission(hr);

        /* Also sync down disk size to underlying LUKS/fscrypt/quota */
        while (arg_and_resize) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "ResizeHome");
                if (r < 0)
                        return bus_log_create_error(r);

                /* Specify UINT64_MAX as size, in which case the underlying disk size will just be synced */
                r = sd_bus_message_append(m, "st", hr->user_name, UINT64_MAX);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, hr);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (arg_and_change_password &&
                            sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN))
                                return log_error_errno(r, "Security token not inserted, refusing.");

                        r = handle_generic_user_record_error(hr->user_name, hr, &error, r, false);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        if (arg_and_change_password)
                log_info("Synchronizing passwords and encryption keys.");

        (void) home_record_reset_human_interaction_permission(hr);

        /* Also sync down passwords to underlying LUKS/fscrypt */
        while (arg_and_change_password) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "ChangePasswordHome");
                if (r < 0)
                        return bus_log_create_error(r);

                /* Specify an empty new secret, in which case the underlying LUKS/fscrypt password will just be synced */
                r = sd_bus_message_append(m, "ss", hr->user_name, "{}");
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, hr);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN))
                                return log_error_errno(r, "Security token not inserted, refusing.");

                        r = handle_generic_user_record_error(hr->user_name, hr, &error, r, false);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        return 0;
}

static int passwd_home(int argc, char *argv[], void *userdata) {
        _cleanup_(user_record_unrefp) UserRecord *old_secret = NULL, *new_secret = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buffer = NULL;
        const char *username;
        int r;

        if (arg_pkcs11_token_uri)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "To change the PKCS#11 security token use 'homectl update --pkcs11-token-uri=%s'.",
                                       special_glyph(SPECIAL_GLYPH_ELLIPSIS));
        if (arg_fido2_device)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "To change the FIDO2 security token use 'homectl update --fido2-device=%s'.",
                                       special_glyph(SPECIAL_GLYPH_ELLIPSIS));
        if (identity_properties_specified())
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The 'passwd' verb does not permit changing other record properties at the same time.");

        if (argc >= 2)
                username = argv[1];
        else {
                buffer = getusername_malloc();
                if (!buffer)
                        return log_oom();

                username = buffer;
        }

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = acquire_passed_secrets(username, &old_secret);
        if (r < 0)
                return r;

        new_secret = user_record_new();
        if (!new_secret)
                return log_oom();

        r = acquire_new_password(username, new_secret, /* suggest = */ true, NULL);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "ChangePasswordHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", username);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, new_secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, old_secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        if (sd_bus_error_has_name(&error, BUS_ERROR_LOW_PASSWORD_QUALITY)) {

                                log_error_errno(r, "%s", bus_error_message(&error, r));

                                r = acquire_new_password(username, new_secret, /* suggest = */ false, NULL);

                        } else if (sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN))

                                /* In the generic handler we'd ask for a password in this case, but when
                                 * changing passwords that's not sufficeint, as we need to acquire all keys
                                 * first. */
                                return log_error_errno(r, "Security token not inserted, refusing.");
                        else
                                r = handle_generic_user_record_error(username, old_secret, &error, r, true);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        return 0;
}

static int parse_disk_size(const char *t, uint64_t *ret) {
        int r;

        assert(t);
        assert(ret);

        if (streq(t, "min"))
                *ret = 0;
        else if (streq(t, "max"))
                *ret = UINT64_MAX-1;  /* Largest size that isn't UINT64_MAX special marker */
        else {
                uint64_t ds;

                r = parse_size(t, 1024, &ds);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse disk size parameter: %s", t);

                if (ds >= UINT64_MAX) /* UINT64_MAX has special meaning for us ("dont change"), refuse */
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Disk size out of range: %s", t);

                *ret = ds;
        }

        return 0;
}

static int resize_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        uint64_t ds = UINT64_MAX;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (arg_disk_size_relative != UINT64_MAX ||
            (argc > 2 && parse_permyriad(argv[2]) >= 0))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Relative disk size specification currently not supported when resizing.");

        if (argc > 2) {
                r = parse_disk_size(argv[2], &ds);
                if (r < 0)
                        return r;
        }

        if (arg_disk_size != UINT64_MAX) {
                if (ds != UINT64_MAX && ds != arg_disk_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Disk size specified twice and doesn't match, refusing.");

                ds = arg_disk_size;
        }

        r = acquire_passed_secrets(argv[1], &secret);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "ResizeHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "st", argv[1], ds);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        r = handle_generic_user_record_error(argv[1], secret, &error, r, false);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        return 0;
}

static int lock_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "LockHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to lock home: %s", bus_error_message(&error, r));
                        if (ret == 0)
                                ret = r;
                }
        }

        return ret;
}

static int unlock_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 0;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(user_record_unrefp) UserRecord *secret = NULL;

                r = acquire_passed_secrets(*i, &secret);
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = bus_message_new_method_call(bus, &m, bus_mgr, "UnlockHome");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", *i);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                r = handle_generic_user_record_error(argv[1], secret, &error, r, false);
                                if (r < 0) {
                                        if (ret == 0)
                                                ret = r;

                                        break;
                                }
                        } else
                                break;
                }
        }

        return ret;
}

static int with_home(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        _cleanup_close_ int acquired_fd = -EBADF;
        _cleanup_strv_free_ char **cmdline  = NULL;
        const char *home;
        int r, ret;
        pid_t pid;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        if (argc < 3) {
                _cleanup_free_ char *shell = NULL;

                /* If no command is specified, spawn a shell */
                r = get_shell(&shell);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire shell: %m");

                cmdline = strv_new(shell);
        } else
                cmdline = strv_copy(argv + 2);
        if (!cmdline)
                return log_oom();

        r = acquire_passed_secrets(argv[1], &secret);
        if (r < 0)
                return r;

        for (;;) {
                r = bus_message_new_method_call(bus, &m, bus_mgr, "AcquireHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", argv[1]);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "b", /* please_suspend = */ getenv_bool("SYSTEMD_PLEASE_SUSPEND_HOME") > 0);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, &reply);
                m = sd_bus_message_unref(m);
                if (r < 0) {
                        r = handle_generic_user_record_error(argv[1], secret, &error, r, false);
                        if (r < 0)
                                return r;

                        sd_bus_error_free(&error);
                } else {
                        int fd;

                        r = sd_bus_message_read(reply, "h", &fd);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        acquired_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                        if (acquired_fd < 0)
                                return log_error_errno(errno, "Failed to duplicate acquired fd: %m");

                        reply = sd_bus_message_unref(reply);
                        break;
                }
        }

        r = bus_call_method(bus, bus_mgr, "GetHomeByName", &error, &reply, "s", argv[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect home: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "usussso", NULL, NULL, NULL, NULL, &home, NULL, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        r = safe_fork("(with)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                if (chdir(home) < 0) {
                        log_error_errno(errno, "Failed to change to directory %s: %m", home);
                        _exit(255);
                }

                execvp(cmdline[0], cmdline);
                log_error_errno(errno, "Failed to execute %s: %m", cmdline[0]);
                _exit(255);
        }

        ret = wait_for_terminate_and_check(cmdline[0], pid, WAIT_LOG_ABNORMAL);

        /* Close the fd that pings the home now. */
        acquired_fd = safe_close(acquired_fd);

        r = bus_message_new_method_call(bus, &m, bus_mgr, "ReleaseHome");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", argv[1]);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_HOME_BUSY))
                        log_notice("Not deactivating home directory of %s, as it is still used.", argv[1]);
                else
                        return log_error_errno(r, "Failed to release user home: %s", bus_error_message(&error, r));
        }

        return ret;
}

static int lock_all_homes(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_message_new_method_call(bus, &m, bus_mgr, "LockAllHomes");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to lock all homes: %s", bus_error_message(&error, r));

        return 0;
}

static int deactivate_all_homes(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_message_new_method_call(bus, &m, bus_mgr, "DeactivateAllHomes");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to deactivate all homes: %s", bus_error_message(&error, r));

        return 0;
}

static int rebalance(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = bus_message_new_method_call(bus, &m, bus_mgr, "Rebalance");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_REBALANCE_NOT_NEEDED))
                        log_info("No homes needed rebalancing.");
                else
                        return log_error_errno(r, "Failed to rebalance: %s", bus_error_message(&error, r));
        } else
                log_info("Completed rebalancing.");

        return 0;
}

static int create_from_credentials(void) {
        _cleanup_close_ int fd = -EBADF;
        int ret = 0, n_created = 0, r;

        fd = open_credentials_dir();
        if (IN_SET(fd, -ENXIO, -ENOENT)) /* Credential env var not set, or dir doesn't exist. */
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open credentials directory: %m");

        _cleanup_free_ DirectoryEntries *des = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &des);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate credentials: %m");

        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *identity = NULL;
                struct dirent *de = *i;
                const char *e;

                if (de->d_type != DT_REG)
                        continue;

                e = startswith(de->d_name, "home.create.");
                if (!e)
                        continue;

                if (!valid_user_group_name(e, 0)) {
                        log_notice("Skipping over credential with name that is not a suitable user name: %s", de->d_name);
                        continue;
                }

                r = sd_json_parse_file_at(
                                /* f= */ NULL,
                                fd,
                                de->d_name,
                                /* flags= */ 0,
                                &identity,
                                /* ret_line= */ NULL,
                                /* ret_column= */ NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse user record in credential '%s', ignoring: %m", de->d_name);
                        continue;
                }

                sd_json_variant *un;
                un = sd_json_variant_by_key(identity, "userName");
                if (un) {
                        if (!sd_json_variant_is_string(un)) {
                                log_warning("User record from credential '%s' contains 'userName' field of invalid type, ignoring.", de->d_name);
                                continue;
                        }

                        if (!streq(sd_json_variant_string(un), e)) {
                                log_warning("User record from credential '%s' contains 'userName' field (%s) that doesn't match credential name (%s), ignoring.", de->d_name, sd_json_variant_string(un), e);
                                continue;
                        }
                } else {
                        r = sd_json_variant_set_field_string(&identity, "userName", e);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to set userName field: %m");
                }

                log_notice("Processing user '%s' from credentials.", e);

                r = create_home_common(identity);
                if (r >= 0)
                        n_created++;

                RET_GATHER(ret, r);
        }

        return ret < 0 ? ret : n_created;
}

static int has_regular_user(void) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        UserDBMatch match = USERDB_MATCH_NULL;
        int r;

        match.disposition_mask = INDEX_TO_MASK(uint64_t, USER_REGULAR);

        r = userdb_all(&match, USERDB_SUPPRESS_SHADOW, &iterator);
        if (r < 0)
                return log_error_errno(r, "Failed to create user enumerator: %m");

        r = userdb_iterator_get(iterator, &match, /* ret= */ NULL);
        if (r == -ESRCH)
                return false;
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate users: %m");

        return true;
}

static int acquire_group_list(char ***ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_strv_free_ char **groups = NULL;
        UserDBMatch match = USERDB_MATCH_NULL;
        int r;

        assert(ret);

        match.disposition_mask = INDEXES_TO_MASK(uint64_t, USER_REGULAR, USER_SYSTEM);

        r = groupdb_all(&match, USERDB_SUPPRESS_SHADOW, &iterator);
        if (r == -ENOLINK)
                log_debug_errno(r, "No groups found. (Didn't check via Varlink.)");
        else if (r == -ESRCH)
                log_debug_errno(r, "No groups found.");
        else if (r < 0)
                return log_debug_errno(r, "Failed to enumerate groups, ignoring: %m");
        else
                for (;;) {
                        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                        r = groupdb_iterator_get(iterator, &match, &gr);
                        if (r == -ESRCH)
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed acquire next group: %m");

                        if (group_record_disposition(gr) == USER_REGULAR) {
                                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                                /* Filter groups here that belong to a specific user, and are named like them */

                                UserDBMatch user_match = USERDB_MATCH_NULL;
                                user_match.disposition_mask = INDEX_TO_MASK(uint64_t, USER_REGULAR);

                                r = userdb_by_name(gr->group_name, &user_match, USERDB_SUPPRESS_SHADOW, &ur);
                                if (r < 0 && r != -ESRCH)
                                        return log_debug_errno(r, "Failed to check if matching user exists for group '%s': %m", gr->group_name);

                                if (r >= 0 && ur->gid == gr->gid)
                                        continue;
                        }

                        r = strv_extend(&groups, gr->group_name);
                        if (r < 0)
                                return log_oom();
                }

        strv_sort(groups);

        *ret = TAKE_PTR(groups);
        return !!*ret;
}

static int create_interactively(void) {
        _cleanup_free_ char *username = NULL;
        int r;

        if (!arg_prompt_new_user) {
                log_debug("Prompting for user creation was not requested.");
                return 0;
        }

        any_key_to_proceed();

        (void) terminal_reset_defensive_locked(STDOUT_FILENO, /* switch_to_text= */ false);

        for (;;) {
                username = mfree(username);

                r = ask_string(&username,
                               "%s Please enter user name to create (empty to skip): ",
                               special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET));
                if (r < 0)
                        return log_error_errno(r, "Failed to query user for username: %m");

                if (isempty(username)) {
                        log_info("No data entered, skipping.");
                        return 0;
                }

                if (!valid_user_group_name(username, /* flags= */ 0)) {
                        log_notice("Specified user name is not a valid UNIX user name, try again: %s", username);
                        continue;
                }

                r = userdb_by_name(username, /* match= */ NULL, USERDB_SUPPRESS_SHADOW, /* ret= */ NULL);
                if (r == -ESRCH)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to check if specified user '%s' already exists: %m", username);

                log_notice("Specified user '%s' exists already, try again.", username);
        }

        r = sd_json_variant_set_field_string(&arg_identity_extra, "userName", username);
        if (r < 0)
                return log_error_errno(r, "Failed to set userName field: %m");

        _cleanup_strv_free_ char **available = NULL, **groups = NULL;

        for (;;) {
                _cleanup_free_ char *s = NULL;
                unsigned u;

                r = ask_string(&s,
                               "%s Please enter an auxiliary group for user %s (empty to continue, \"list\" to list available groups): ",
                               special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET), username);
                if (r < 0)
                        return log_error_errno(r, "Failed to query user for auxiliary group: %m");

                if (isempty(s))
                        break;

                if (streq(s, "list")) {
                        if (!available) {
                                r = acquire_group_list(&available);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to enumerate available groups, ignoring: %m");
                                if (r == 0)
                                        log_notice("Did not find any available groups");
                                if (r <= 0)
                                        continue;
                        }

                        r = show_menu(available, /*n_columns=*/ 3, /*width=*/ 20, /*percentage=*/ 60);
                        if (r < 0)
                                return r;

                        putchar('\n');
                        continue;
                };

                if (available) {
                        r = safe_atou(s, &u);
                        if (r >= 0) {
                                if (u <= 0 || u > strv_length(available)) {
                                        log_error("Specified entry number out of range.");
                                        continue;
                                }

                                log_info("Selected '%s'.", available[u-1]);

                                r = strv_extend(&groups, available[u-1]);
                                if (r < 0)
                                        return log_oom();

                                continue;
                        }
                }

                if (!valid_user_group_name(s, /* flags= */ 0)) {
                        log_notice("Specified group name is not a valid UNIX group name, try again: %s", s);
                        continue;
                }

                r = groupdb_by_name(s, /* match= */ NULL, USERDB_SUPPRESS_SHADOW|USERDB_EXCLUDE_DYNAMIC_USER, /*ret=*/ NULL);
                if (r == -ESRCH) {
                        log_notice("Specified auxiliary group does not exist, try again: %s", s);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to check if specified group '%s' already exists: %m", s);

                log_info("Selected '%s'.", s);

                r = strv_extend(&groups, s);
                if (r < 0)
                        return log_oom();
        }

        if (groups) {
                strv_sort_uniq(groups);

                r = sd_json_variant_set_field_strv(&arg_identity_extra, "memberOf", groups);
                if (r < 0)
                        return log_error_errno(r, "Failed to set memberOf field: %m");
        }

        _cleanup_free_ char *shell = NULL;

        for (;;) {
                shell = mfree(shell);

                r = ask_string(&shell,
                               "%s Please enter the shell to use for user %s (empty to skip): ",
                               special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET), username);
                if (r < 0)
                        return log_error_errno(r, "Failed to query user for username: %m");

                if (isempty(shell)) {
                        log_info("No data entered, skipping.");
                        break;
                }

                if (!valid_shell(shell)) {
                        log_notice("Specified shell is not a valid UNIX shell path, try again: %s", shell);
                        continue;
                }

                r = RET_NERRNO(access(shell, X_OK));
                if (r >= 0)
                        break;

                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to check if shell %s exists: %m", shell);

                log_notice("Specified shell '%s' is not installed, try another one.", shell);
        }

        if (shell) {
                log_info("Selected %s as the shell for user %s", shell, username);

                r = sd_json_variant_set_field_string(&arg_identity_extra, "shell", shell);
                if (r < 0)
                        return log_error_errno(r, "Failed to set shell field: %m");
        }

        return create_home_common(/* input= */ NULL);
}

static int verb_firstboot(int argc, char *argv[], void *userdata) {
        int r;

        /* Let's honour the systemd.firstboot kernel command line option, just like the systemd-firstboot
         * tool. */

        bool enabled;
        r = proc_cmdline_get_bool("systemd.firstboot", /* flags = */ 0, &enabled);
        if (r < 0)
                return log_error_errno(r, "Failed to parse systemd.firstboot= kernel command line argument, ignoring: %m");
        if (r > 0 && !enabled) {
                log_debug("Found systemd.firstboot=no kernel command line argument, turning off all prompts.");
                arg_prompt_new_user = false;
        }

        r = create_from_credentials();
        if (r < 0)
                return r;
        if (r > 0) /* Already created users from credentials */
                return 0;

        r = has_regular_user();
        if (r < 0)
                return r;
        if (r > 0) {
                log_info("Regular user already present in user database, skipping user creation.");
                return 0;
        }

        return create_interactively();
}

static int drop_from_identity(const char *field) {
        int r;

        assert(field);

        /* If we are called to update an identity record and drop some field, let's keep track of what to
         * remove from the old record */
        r = strv_extend(&arg_identity_filter, field);
        if (r < 0)
                return log_oom();

        /* Let's also drop the field if it was previously set to a new value on the same command line */
        r = sd_json_variant_filter(&arg_identity_extra, STRV_MAKE(field));
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        r = sd_json_variant_filter(&arg_identity_extra_this_machine, STRV_MAKE(field));
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        r = sd_json_variant_filter(&arg_identity_extra_privileged, STRV_MAKE(field));
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("homectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%2$sCreate, manipulate or inspect home directories.%3$s\n"
               "\n%4$sCommands:%5$s\n"
               "  list                         List home areas\n"
               "  activate USER…               Activate a home area\n"
               "  deactivate USER…             Deactivate a home area\n"
               "  inspect USER…                Inspect a home area\n"
               "  authenticate USER…           Authenticate a home area\n"
               "  create USER                  Create a home area\n"
               "  remove USER…                 Remove a home area\n"
               "  update USER                  Update a home area\n"
               "  passwd USER                  Change password of a home area\n"
               "  resize USER SIZE             Resize a home area\n"
               "  lock USER…                   Temporarily lock an active home area\n"
               "  unlock USER…                 Unlock a temporarily locked home area\n"
               "  lock-all                     Lock all suitable home areas\n"
               "  deactivate-all               Deactivate all active home areas\n"
               "  rebalance                    Rebalance free space between home areas\n"
               "  with USER [COMMAND…]         Run shell or command with access to a home area\n"
               "  firstboot                    Run first-boot home area creation wizard\n"
               "\n%4$sOptions:%5$s\n"
               "  -h --help                    Show this help\n"
               "     --version                 Show package version\n"
               "     --no-pager                Do not pipe output into a pager\n"
               "     --no-legend               Do not show the headers and footers\n"
               "     --no-ask-password         Do not ask for system passwords\n"
               "     --offline                 Don't update record embedded in home directory\n"
               "  -H --host=[USER@]HOST        Operate on remote host\n"
               "  -M --machine=CONTAINER       Operate on local container\n"
               "     --identity=PATH           Read JSON identity from file\n"
               "     --json=FORMAT             Output inspection data in JSON (takes one of\n"
               "                               pretty, short, off)\n"
               "  -j                           Equivalent to --json=pretty (on TTY) or\n"
               "                               --json=short (otherwise)\n"
               "     --export-format=          Strip JSON inspection data (full, stripped,\n"
               "                               minimal)\n"
               "  -E                           When specified once equals -j --export-format=\n"
               "                               stripped, when specified twice equals\n"
               "                               -j --export-format=minimal\n"
               "     --prompt-new-user         firstboot: Query user interactively for user\n"
               "                               to create\n"
               "\n%4$sGeneral User Record Properties:%5$s\n"
               "  -c --real-name=REALNAME      Real name for user\n"
               "     --realm=REALM             Realm to create user in\n"
               "     --alias=ALIAS             Define alias usernames for this account\n"
               "     --email-address=EMAIL     Email address for user\n"
               "     --location=LOCATION       Set location of user on earth\n"
               "     --icon-name=NAME          Icon name for user\n"
               "  -d --home-dir=PATH           Home directory\n"
               "  -u --uid=UID                 Numeric UID for user\n"
               "  -G --member-of=GROUP         Add user to group\n"
               "     --capability-bounding-set=CAPS\n"
               "                               Bounding POSIX capability set\n"
               "     --capability-ambient-set=CAPS\n"
               "                               Ambient POSIX capability set\n"
               "     --access-mode=MODE        User home directory access mode\n"
               "     --umask=MODE              Umask for user when logging in\n"
               "     --skel=PATH               Skeleton directory to use\n"
               "     --shell=PATH              Shell for account\n"
               "     --setenv=VARIABLE[=VALUE] Set an environment variable at log-in\n"
               "     --timezone=TIMEZONE       Set a time-zone\n"
               "     --language=LOCALE         Set preferred languages\n"
               "\n%4$sAuthentication User Record Properties:%5$s\n"
               "     --ssh-authorized-keys=KEYS\n"
               "                               Specify SSH public keys\n"
               "     --pkcs11-token-uri=URI    URI to PKCS#11 security token containing\n"
               "                               private key and matching X.509 certificate\n"
               "     --fido2-device=PATH       Path to FIDO2 hidraw device with hmac-secret\n"
               "                               extension\n"
               "     --fido2-with-client-pin=BOOL\n"
               "                               Whether to require entering a PIN to unlock the\n"
               "                               account\n"
               "     --fido2-with-user-presence=BOOL\n"
               "                               Whether to require user presence to unlock the\n"
               "                               account\n"
               "     --fido2-with-user-verification=BOOL\n"
               "                               Whether to require user verification to unlock\n"
               "                               the account\n"
               "     --recovery-key=BOOL       Add a recovery key\n"
               "\n%4$sBlob Directory User Record Properties:%5$s\n"
               "  -b --blob=[FILENAME=]PATH\n"
               "                               Path to a replacement blob directory, or replace\n"
               "                               an individual files in the blob directory.\n"
               "     --avatar=PATH             Path to user avatar picture\n"
               "     --login-background=PATH   Path to user login background picture\n"
               "\n%4$sAccount Management User Record Properties:%5$s\n"
               "     --locked=BOOL             Set locked account state\n"
               "     --not-before=TIMESTAMP    Do not allow logins before\n"
               "     --not-after=TIMESTAMP     Do not allow logins after\n"
               "     --rate-limit-interval=SECS\n"
               "                               Login rate-limit interval in seconds\n"
               "     --rate-limit-burst=NUMBER\n"
               "                               Login rate-limit attempts per interval\n"
               "\n%4$sPassword Policy User Record Properties:%5$s\n"
               "     --password-hint=HINT      Set Password hint\n"
               "     --enforce-password-policy=BOOL\n"
               "                               Control whether to enforce system's password\n"
               "                               policy for this user\n"
               "  -P                           Same as --enforce-password-password=no\n"
               "     --password-change-now=BOOL\n"
               "                               Require the password to be changed on next login\n"
               "     --password-change-min=TIME\n"
               "                               Require minimum time between password changes\n"
               "     --password-change-max=TIME\n"
               "                               Require maximum time between password changes\n"
               "     --password-change-warn=TIME\n"
               "                               How much time to warn before password expiry\n"
               "     --password-change-inactive=TIME\n"
               "                               How much time to block password after expiry\n"
               "\n%4$sResource Management User Record Properties:%5$s\n"
               "     --disk-size=BYTES         Size to assign the user on disk\n"
               "     --nice=NICE               Nice level for user\n"
               "     --rlimit=LIMIT=VALUE[:VALUE]\n"
               "                               Set resource limits\n"
               "     --tasks-max=MAX           Set maximum number of per-user tasks\n"
               "     --memory-high=BYTES       Set high memory threshold in bytes\n"
               "     --memory-max=BYTES        Set maximum memory limit\n"
               "     --cpu-weight=WEIGHT       Set CPU weight\n"
               "     --io-weight=WEIGHT        Set IO weight\n"
               "     --tmp-limit=BYTES|PERCENT Set limit on /tmp/\n"
               "     --dev-shm-limit=BYTES|PERCENT\n"
               "                               Set limit on /dev/shm/\n"
               "\n%4$sStorage User Record Properties:%5$s\n"
               "     --storage=STORAGE         Storage type to use (luks, fscrypt, directory,\n"
               "                               subvolume, cifs)\n"
               "     --image-path=PATH         Path to image file/directory\n"
               "     --drop-caches=BOOL        Whether to automatically drop caches on logout\n"
               "\n%4$sLUKS Storage User Record Properties:%5$s\n"
               "     --fs-type=TYPE            File system type to use in case of luks\n"
               "                               storage (btrfs, ext4, xfs)\n"
               "     --luks-discard=BOOL       Whether to use 'discard' feature of file system\n"
               "                               when activated (mounted)\n"
               "     --luks-offline-discard=BOOL\n"
               "                               Whether to trim file on logout\n"
               "     --luks-cipher=CIPHER      Cipher to use for LUKS encryption\n"
               "     --luks-cipher-mode=MODE   Cipher mode to use for LUKS encryption\n"
               "     --luks-volume-key-size=BITS\n"
               "                               Volume key size to use for LUKS encryption\n"
               "     --luks-pbkdf-type=TYPE    Password-based Key Derivation Function to use\n"
               "     --luks-pbkdf-hash-algorithm=ALGORITHM\n"
               "                               PBKDF hash algorithm to use\n"
               "     --luks-pbkdf-time-cost=SECS\n"
               "                               Time cost for PBKDF in seconds\n"
               "     --luks-pbkdf-memory-cost=BYTES\n"
               "                               Memory cost for PBKDF in bytes\n"
               "     --luks-pbkdf-parallel-threads=NUMBER\n"
               "                               Number of parallel threads for PKBDF\n"
               "     --luks-sector-size=BYTES\n"
               "                               Sector size for LUKS encryption in bytes\n"
               "     --luks-extra-mount-options=OPTIONS\n"
               "                               LUKS extra mount options\n"
               "     --auto-resize-mode=MODE   Automatically grow/shrink home on login/logout\n"
               "     --rebalance-weight=WEIGHT Weight while rebalancing\n"
               "\n%4$sMounting User Record Properties:%5$s\n"
               "     --nosuid=BOOL             Control the 'nosuid' flag of the home mount\n"
               "     --nodev=BOOL              Control the 'nodev' flag of the home mount\n"
               "     --noexec=BOOL             Control the 'noexec' flag of the home mount\n"
               "\n%4$sCIFS User Record Properties:%5$s\n"
               "     --cifs-domain=DOMAIN      CIFS (Windows) domain\n"
               "     --cifs-user-name=USER     CIFS (Windows) user name\n"
               "     --cifs-service=SERVICE    CIFS (Windows) service to mount as home area\n"
               "     --cifs-extra-mount-options=OPTIONS\n"
               "                               CIFS (Windows) extra mount options\n"
               "\n%4$sLogin Behaviour User Record Properties:%5$s\n"
               "     --stop-delay=SECS         How long to leave user services running after\n"
               "                               logout\n"
               "     --kill-processes=BOOL     Whether to kill user processes when sessions\n"
               "                               terminate\n"
               "     --auto-login=BOOL         Try to log this user in automatically\n"
               "     --session-launcher=LAUNCHER\n"
               "                               Preferred session launcher file\n"
               "     --session-type=TYPE       Preferred session type\n"
               "\nSee the %6$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        _cleanup_strv_free_ char **arg_languages = NULL;

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_NO_ASK_PASSWORD,
                ARG_OFFLINE,
                ARG_REALM,
                ARG_ALIAS,
                ARG_EMAIL_ADDRESS,
                ARG_DISK_SIZE,
                ARG_ACCESS_MODE,
                ARG_STORAGE,
                ARG_FS_TYPE,
                ARG_IMAGE_PATH,
                ARG_UMASK,
                ARG_LUKS_DISCARD,
                ARG_LUKS_OFFLINE_DISCARD,
                ARG_JSON,
                ARG_SETENV,
                ARG_TIMEZONE,
                ARG_LANGUAGE,
                ARG_LOCKED,
                ARG_SSH_AUTHORIZED_KEYS,
                ARG_LOCATION,
                ARG_ICON_NAME,
                ARG_PASSWORD_HINT,
                ARG_NICE,
                ARG_RLIMIT,
                ARG_NOT_BEFORE,
                ARG_NOT_AFTER,
                ARG_LUKS_CIPHER,
                ARG_LUKS_CIPHER_MODE,
                ARG_LUKS_VOLUME_KEY_SIZE,
                ARG_NOSUID,
                ARG_NODEV,
                ARG_NOEXEC,
                ARG_CIFS_DOMAIN,
                ARG_CIFS_USER_NAME,
                ARG_CIFS_SERVICE,
                ARG_CIFS_EXTRA_MOUNT_OPTIONS,
                ARG_TASKS_MAX,
                ARG_MEMORY_HIGH,
                ARG_MEMORY_MAX,
                ARG_CPU_WEIGHT,
                ARG_IO_WEIGHT,
                ARG_LUKS_PBKDF_TYPE,
                ARG_LUKS_PBKDF_HASH_ALGORITHM,
                ARG_LUKS_PBKDF_FORCE_ITERATIONS,
                ARG_LUKS_PBKDF_TIME_COST,
                ARG_LUKS_PBKDF_MEMORY_COST,
                ARG_LUKS_PBKDF_PARALLEL_THREADS,
                ARG_LUKS_SECTOR_SIZE,
                ARG_RATE_LIMIT_INTERVAL,
                ARG_RATE_LIMIT_BURST,
                ARG_STOP_DELAY,
                ARG_KILL_PROCESSES,
                ARG_ENFORCE_PASSWORD_POLICY,
                ARG_PASSWORD_CHANGE_NOW,
                ARG_PASSWORD_CHANGE_MIN,
                ARG_PASSWORD_CHANGE_MAX,
                ARG_PASSWORD_CHANGE_WARN,
                ARG_PASSWORD_CHANGE_INACTIVE,
                ARG_EXPORT_FORMAT,
                ARG_AUTO_LOGIN,
                ARG_SESSION_LAUNCHER,
                ARG_SESSION_TYPE,
                ARG_PKCS11_TOKEN_URI,
                ARG_FIDO2_DEVICE,
                ARG_FIDO2_WITH_PIN,
                ARG_FIDO2_WITH_UP,
                ARG_FIDO2_WITH_UV,
                ARG_RECOVERY_KEY,
                ARG_AND_RESIZE,
                ARG_AND_CHANGE_PASSWORD,
                ARG_DROP_CACHES,
                ARG_LUKS_EXTRA_MOUNT_OPTIONS,
                ARG_AUTO_RESIZE_MODE,
                ARG_REBALANCE_WEIGHT,
                ARG_FIDO2_CRED_ALG,
                ARG_CAPABILITY_BOUNDING_SET,
                ARG_CAPABILITY_AMBIENT_SET,
                ARG_PROMPT_NEW_USER,
                ARG_AVATAR,
                ARG_LOGIN_BACKGROUND,
                ARG_TMP_LIMIT,
                ARG_DEV_SHM_LIMIT,
        };

        static const struct option options[] = {
                { "help",                         no_argument,       NULL, 'h'                             },
                { "version",                      no_argument,       NULL, ARG_VERSION                     },
                { "no-pager",                     no_argument,       NULL, ARG_NO_PAGER                    },
                { "no-legend",                    no_argument,       NULL, ARG_NO_LEGEND                   },
                { "no-ask-password",              no_argument,       NULL, ARG_NO_ASK_PASSWORD             },
                { "offline",                      no_argument,       NULL, ARG_OFFLINE                     },
                { "host",                         required_argument, NULL, 'H'                             },
                { "machine",                      required_argument, NULL, 'M'                             },
                { "identity",                     required_argument, NULL, 'I'                             },
                { "real-name",                    required_argument, NULL, 'c'                             },
                { "comment",                      required_argument, NULL, 'c'                             }, /* Compat alias to keep thing in sync with useradd(8) */
                { "realm",                        required_argument, NULL, ARG_REALM                       },
                { "alias",                        required_argument, NULL, ARG_ALIAS                       },
                { "email-address",                required_argument, NULL, ARG_EMAIL_ADDRESS               },
                { "location",                     required_argument, NULL, ARG_LOCATION                    },
                { "password-hint",                required_argument, NULL, ARG_PASSWORD_HINT               },
                { "icon-name",                    required_argument, NULL, ARG_ICON_NAME                   },
                { "home-dir",                     required_argument, NULL, 'd'                             }, /* Compatible with useradd(8) */
                { "uid",                          required_argument, NULL, 'u'                             }, /* Compatible with useradd(8) */
                { "member-of",                    required_argument, NULL, 'G'                             },
                { "groups",                       required_argument, NULL, 'G'                             }, /* Compat alias to keep thing in sync with useradd(8) */
                { "skel",                         required_argument, NULL, 'k'                             }, /* Compatible with useradd(8) */
                { "shell",                        required_argument, NULL, 's'                             }, /* Compatible with useradd(8) */
                { "setenv",                       required_argument, NULL, ARG_SETENV                      },
                { "timezone",                     required_argument, NULL, ARG_TIMEZONE                    },
                { "language",                     required_argument, NULL, ARG_LANGUAGE                    },
                { "locked",                       required_argument, NULL, ARG_LOCKED                      },
                { "not-before",                   required_argument, NULL, ARG_NOT_BEFORE                  },
                { "not-after",                    required_argument, NULL, ARG_NOT_AFTER                   },
                { "expiredate",                   required_argument, NULL, 'e'                             }, /* Compat alias to keep thing in sync with useradd(8) */
                { "ssh-authorized-keys",          required_argument, NULL, ARG_SSH_AUTHORIZED_KEYS         },
                { "disk-size",                    required_argument, NULL, ARG_DISK_SIZE                   },
                { "access-mode",                  required_argument, NULL, ARG_ACCESS_MODE                 },
                { "umask",                        required_argument, NULL, ARG_UMASK                       },
                { "nice",                         required_argument, NULL, ARG_NICE                        },
                { "rlimit",                       required_argument, NULL, ARG_RLIMIT                      },
                { "tasks-max",                    required_argument, NULL, ARG_TASKS_MAX                   },
                { "memory-high",                  required_argument, NULL, ARG_MEMORY_HIGH                 },
                { "memory-max",                   required_argument, NULL, ARG_MEMORY_MAX                  },
                { "cpu-weight",                   required_argument, NULL, ARG_CPU_WEIGHT                  },
                { "io-weight",                    required_argument, NULL, ARG_IO_WEIGHT                   },
                { "storage",                      required_argument, NULL, ARG_STORAGE                     },
                { "image-path",                   required_argument, NULL, ARG_IMAGE_PATH                  },
                { "fs-type",                      required_argument, NULL, ARG_FS_TYPE                     },
                { "luks-discard",                 required_argument, NULL, ARG_LUKS_DISCARD                },
                { "luks-offline-discard",         required_argument, NULL, ARG_LUKS_OFFLINE_DISCARD        },
                { "luks-cipher",                  required_argument, NULL, ARG_LUKS_CIPHER                 },
                { "luks-cipher-mode",             required_argument, NULL, ARG_LUKS_CIPHER_MODE            },
                { "luks-volume-key-size",         required_argument, NULL, ARG_LUKS_VOLUME_KEY_SIZE        },
                { "luks-pbkdf-type",              required_argument, NULL, ARG_LUKS_PBKDF_TYPE             },
                { "luks-pbkdf-hash-algorithm",    required_argument, NULL, ARG_LUKS_PBKDF_HASH_ALGORITHM   },
                { "luks-pbkdf-force-iterations",  required_argument, NULL, ARG_LUKS_PBKDF_FORCE_ITERATIONS },
                { "luks-pbkdf-time-cost",         required_argument, NULL, ARG_LUKS_PBKDF_TIME_COST        },
                { "luks-pbkdf-memory-cost",       required_argument, NULL, ARG_LUKS_PBKDF_MEMORY_COST      },
                { "luks-pbkdf-parallel-threads",  required_argument, NULL, ARG_LUKS_PBKDF_PARALLEL_THREADS },
                { "luks-sector-size",             required_argument, NULL, ARG_LUKS_SECTOR_SIZE            },
                { "nosuid",                       required_argument, NULL, ARG_NOSUID                      },
                { "nodev",                        required_argument, NULL, ARG_NODEV                       },
                { "noexec",                       required_argument, NULL, ARG_NOEXEC                      },
                { "cifs-user-name",               required_argument, NULL, ARG_CIFS_USER_NAME              },
                { "cifs-domain",                  required_argument, NULL, ARG_CIFS_DOMAIN                 },
                { "cifs-service",                 required_argument, NULL, ARG_CIFS_SERVICE                },
                { "cifs-extra-mount-options",     required_argument, NULL, ARG_CIFS_EXTRA_MOUNT_OPTIONS    },
                { "rate-limit-interval",          required_argument, NULL, ARG_RATE_LIMIT_INTERVAL         },
                { "rate-limit-burst",             required_argument, NULL, ARG_RATE_LIMIT_BURST            },
                { "stop-delay",                   required_argument, NULL, ARG_STOP_DELAY                  },
                { "kill-processes",               required_argument, NULL, ARG_KILL_PROCESSES              },
                { "enforce-password-policy",      required_argument, NULL, ARG_ENFORCE_PASSWORD_POLICY     },
                { "password-change-now",          required_argument, NULL, ARG_PASSWORD_CHANGE_NOW         },
                { "password-change-min",          required_argument, NULL, ARG_PASSWORD_CHANGE_MIN         },
                { "password-change-max",          required_argument, NULL, ARG_PASSWORD_CHANGE_MAX         },
                { "password-change-warn",         required_argument, NULL, ARG_PASSWORD_CHANGE_WARN        },
                { "password-change-inactive",     required_argument, NULL, ARG_PASSWORD_CHANGE_INACTIVE    },
                { "auto-login",                   required_argument, NULL, ARG_AUTO_LOGIN                  },
                { "session-launcher",             required_argument, NULL, ARG_SESSION_LAUNCHER,           },
                { "session-type",                 required_argument, NULL, ARG_SESSION_TYPE,               },
                { "json",                         required_argument, NULL, ARG_JSON                        },
                { "export-format",                required_argument, NULL, ARG_EXPORT_FORMAT               },
                { "pkcs11-token-uri",             required_argument, NULL, ARG_PKCS11_TOKEN_URI            },
                { "fido2-credential-algorithm",   required_argument, NULL, ARG_FIDO2_CRED_ALG              },
                { "fido2-device",                 required_argument, NULL, ARG_FIDO2_DEVICE                },
                { "fido2-with-client-pin",        required_argument, NULL, ARG_FIDO2_WITH_PIN              },
                { "fido2-with-user-presence",     required_argument, NULL, ARG_FIDO2_WITH_UP               },
                { "fido2-with-user-verification", required_argument, NULL, ARG_FIDO2_WITH_UV               },
                { "recovery-key",                 required_argument, NULL, ARG_RECOVERY_KEY                },
                { "and-resize",                   required_argument, NULL, ARG_AND_RESIZE                  },
                { "and-change-password",          required_argument, NULL, ARG_AND_CHANGE_PASSWORD         },
                { "drop-caches",                  required_argument, NULL, ARG_DROP_CACHES                 },
                { "luks-extra-mount-options",     required_argument, NULL, ARG_LUKS_EXTRA_MOUNT_OPTIONS    },
                { "auto-resize-mode",             required_argument, NULL, ARG_AUTO_RESIZE_MODE            },
                { "rebalance-weight",             required_argument, NULL, ARG_REBALANCE_WEIGHT            },
                { "capability-bounding-set",      required_argument, NULL, ARG_CAPABILITY_BOUNDING_SET     },
                { "capability-ambient-set",       required_argument, NULL, ARG_CAPABILITY_AMBIENT_SET      },
                { "prompt-new-user",              no_argument,       NULL, ARG_PROMPT_NEW_USER             },
                { "blob",                         required_argument, NULL, 'b'                             },
                { "avatar",                       required_argument, NULL, ARG_AVATAR                      },
                { "login-background",             required_argument, NULL, ARG_LOGIN_BACKGROUND            },
                { "tmp-limit",                    required_argument, NULL, ARG_TMP_LIMIT                   },
                { "dev-shm-limit",                required_argument, NULL, ARG_DEV_SHM_LIMIT               },
                {}
        };

        int r;

        assert(argc >= 0);
        assert(argv);

        for (;;) {
                int c;

                c = getopt_long(argc, argv, "hH:M:I:c:d:u:G:k:s:e:b:jPE", options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_OFFLINE:
                        arg_offline = true;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case 'I':
                        arg_identity = optarg;
                        break;

                case 'c':
                        if (isempty(optarg)) {
                                r = drop_from_identity("realName");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!valid_gecos(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Real name '%s' not a valid GECOS field.", optarg);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "realName", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set realName field: %m");

                        break;

                case ARG_ALIAS: {
                        if (isempty(optarg)) {
                                r = drop_from_identity("aliases");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        for (const char *p = optarg;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse alias list: %m");
                                if (r == 0)
                                        break;

                                if (!valid_user_group_name(word, 0))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid alias user name %s.", word);

                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *av =
                                        sd_json_variant_ref(sd_json_variant_by_key(arg_identity_extra, "aliases"));

                                _cleanup_strv_free_ char **list = NULL;
                                r = sd_json_variant_strv(av, &list);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse group list: %m");

                                r = strv_extend(&list, word);
                                if (r < 0)
                                        return log_oom();

                                strv_sort_uniq(list);

                                av = sd_json_variant_unref(av);
                                r = sd_json_variant_new_array_strv(&av, list);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create alias list JSON: %m");

                                r = sd_json_variant_set_field(&arg_identity_extra, "aliases", av);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update alias list: %m");
                        }

                        break;
                }

                case 'd': {
                        _cleanup_free_ char *hd = NULL;

                        if (isempty(optarg)) {
                                r = drop_from_identity("homeDirectory");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_path_argument(optarg, false, &hd);
                        if (r < 0)
                                return r;

                        if (!valid_home(hd))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Home directory '%s' not valid.", hd);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "homeDirectory", hd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set homeDirectory field: %m");

                        break;
                }

                case ARG_REALM:
                        if (isempty(optarg)) {
                                r = drop_from_identity("realm");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = dns_name_is_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether realm '%s' is a valid DNS domain: %m", optarg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Realm '%s' is not a valid DNS domain.", optarg);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "realm", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set realm field: %m");
                        break;

                case ARG_EMAIL_ADDRESS:
                case ARG_LOCATION:
                case ARG_ICON_NAME:
                case ARG_CIFS_USER_NAME:
                case ARG_CIFS_DOMAIN:
                case ARG_CIFS_EXTRA_MOUNT_OPTIONS:
                case ARG_LUKS_EXTRA_MOUNT_OPTIONS:
                case ARG_SESSION_LAUNCHER:
                case ARG_SESSION_TYPE: {

                        const char *field =
                                           c == ARG_EMAIL_ADDRESS ? "emailAddress" :
                                                c == ARG_LOCATION ? "location" :
                                               c == ARG_ICON_NAME ? "iconName" :
                                          c == ARG_CIFS_USER_NAME ? "cifsUserName" :
                                             c == ARG_CIFS_DOMAIN ? "cifsDomain" :
                                c == ARG_CIFS_EXTRA_MOUNT_OPTIONS ? "cifsExtraMountOptions" :
                                c == ARG_LUKS_EXTRA_MOUNT_OPTIONS ? "luksExtraMountOptions" :
                                        c == ARG_SESSION_LAUNCHER ? "preferredSessionLauncher" :
                                            c == ARG_SESSION_TYPE ? "preferredSessionType" :
                                                                    NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = sd_json_variant_set_field_string(&arg_identity_extra, field, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_CIFS_SERVICE:
                        if (isempty(optarg)) {
                                r = drop_from_identity("cifsService");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_cifs_service(optarg, NULL, NULL, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to validate CIFS service name: %s", optarg);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "cifsService", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set cifsService field: %m");

                        break;

                case ARG_PASSWORD_HINT:
                        if (isempty(optarg)) {
                                r = drop_from_identity("passwordHint");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = sd_json_variant_set_field_string(&arg_identity_extra_privileged, "passwordHint", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set passwordHint field: %m");

                        string_erase(optarg);
                        break;

                case ARG_NICE: {
                        int nc;

                        if (isempty(optarg)) {
                                r = drop_from_identity("niceLevel");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = parse_nice(optarg, &nc);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse nice level: %s", optarg);

                        r = sd_json_variant_set_field_integer(&arg_identity_extra, "niceLevel", nc);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set niceLevel field: %m");

                        break;
                }

                case ARG_RLIMIT: {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jcur = NULL, *jmax = NULL;
                        _cleanup_free_ char *field = NULL, *t = NULL;
                        const char *eq;
                        struct rlimit rl;
                        int l;

                        if (isempty(optarg)) {
                                /* Remove all resource limits */

                                r = drop_from_identity("resourceLimits");
                                if (r < 0)
                                        return r;

                                arg_identity_filter_rlimits = strv_free(arg_identity_filter_rlimits);
                                arg_identity_extra_rlimits = sd_json_variant_unref(arg_identity_extra_rlimits);
                                break;
                        }

                        eq = strchr(optarg, '=');
                        if (!eq)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't parse resource limit assignment: %s", optarg);

                        field = strndup(optarg, eq - optarg);
                        if (!field)
                                return log_oom();

                        l = rlimit_from_string_harder(field);
                        if (l < 0)
                                return log_error_errno(l, "Unknown resource limit type: %s", field);

                        if (isempty(eq + 1)) {
                                /* Remove only the specific rlimit */

                                r = strv_extend(&arg_identity_filter_rlimits, rlimit_to_string(l));
                                if (r < 0)
                                        return r;

                                r = sd_json_variant_filter(&arg_identity_extra_rlimits, STRV_MAKE(field));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to filter JSON identity data: %m");

                                break;
                        }

                        r = rlimit_parse(l, eq + 1, &rl);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resource limit value: %s", eq + 1);

                        r = rl.rlim_cur == RLIM_INFINITY ? sd_json_variant_new_null(&jcur) : sd_json_variant_new_unsigned(&jcur, rl.rlim_cur);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate current integer: %m");

                        r = rl.rlim_max == RLIM_INFINITY ? sd_json_variant_new_null(&jmax) : sd_json_variant_new_unsigned(&jmax, rl.rlim_max);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate maximum integer: %m");

                        t = strjoin("RLIMIT_", rlimit_to_string(l));
                        if (!t)
                                return log_oom();

                        r = sd_json_variant_set_fieldbo(
                                        &arg_identity_extra_rlimits, t,
                                        SD_JSON_BUILD_PAIR("cur", SD_JSON_BUILD_VARIANT(jcur)),
                                        SD_JSON_BUILD_PAIR("max", SD_JSON_BUILD_VARIANT(jmax)));
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", rlimit_to_string(l));

                        break;
                }

                case 'u': {
                        uid_t uid;

                        if (isempty(optarg)) {
                                r = drop_from_identity("uid");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_uid(optarg, &uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse UID '%s'.", optarg);

                        if (uid_is_system(uid))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID " UID_FMT " is in system range, refusing.", uid);
                        if (uid_is_dynamic(uid))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID " UID_FMT " is in dynamic range, refusing.", uid);
                        if (uid == UID_NOBODY)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID " UID_FMT " is nobody UID, refusing.", uid);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, "uid", uid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set realm field: %m");

                        break;
                }

                case 'k':
                case ARG_IMAGE_PATH: {
                        const char *field = c == 'k' ? "skeletonDirectory" : "imagePath";
                        _cleanup_free_ char *v = NULL;

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_path_argument(optarg, false, &v);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_set_field_string(&arg_identity_extra_this_machine, field, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", v);

                        break;
                }

                case 's':
                        if (isempty(optarg)) {
                                r = drop_from_identity("shell");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!valid_shell(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Shell '%s' not valid.", optarg);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "shell", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set shell field: %m");

                        break;

                case ARG_SETENV: {
                        _cleanup_free_ char **l = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ne = NULL;
                        sd_json_variant *e;

                        if (isempty(optarg)) {
                                r = drop_from_identity("environment");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        e = sd_json_variant_by_key(arg_identity_extra, "environment");
                        if (e) {
                                r = sd_json_variant_strv(e, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse JSON environment field: %m");
                        }

                        r = strv_env_replace_strdup_passthrough(&l, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", optarg);

                        strv_sort(l);

                        r = sd_json_variant_new_array_strv(&ne, l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate environment list JSON: %m");

                        r = sd_json_variant_set_field(&arg_identity_extra, "environment", ne);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set environment list: %m");

                        break;
                }

                case ARG_TIMEZONE:

                        if (isempty(optarg)) {
                                r = drop_from_identity("timeZone");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!timezone_is_valid(optarg, LOG_DEBUG))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Timezone '%s' is not valid.", optarg);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "timeZone", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set timezone field: %m");

                        break;

                case ARG_LANGUAGE: {
                        const char *p = optarg;

                        if (isempty(p)) {
                                r = drop_from_identity("preferredLanguage");
                                if (r < 0)
                                        return r;

                                r = drop_from_identity("additionalLanguages");
                                if (r < 0)
                                        return r;

                                arg_languages = strv_free(arg_languages);
                                break;
                        }

                        for (;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, ",:", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse locale list: %m");
                                if (r == 0)
                                        break;

                                if (!locale_is_valid(word))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale '%s' is not valid.", word);

                                if (locale_is_installed(word) <= 0)
                                        log_warning("Locale '%s' is not installed, accepting anyway.", word);

                                r = strv_consume(&arg_languages, TAKE_PTR(word));
                                if (r < 0)
                                        return log_oom();

                                strv_uniq(arg_languages);
                        }

                        break;
                }

                case ARG_NOSUID:
                case ARG_NODEV:
                case ARG_NOEXEC:
                case ARG_LOCKED:
                case ARG_KILL_PROCESSES:
                case ARG_ENFORCE_PASSWORD_POLICY:
                case ARG_AUTO_LOGIN:
                case ARG_PASSWORD_CHANGE_NOW: {
                        const char *field =
                                                 c == ARG_LOCKED ? "locked" :
                                                 c == ARG_NOSUID ? "mountNoSuid" :
                                                  c == ARG_NODEV ? "mountNoDevices" :
                                                 c == ARG_NOEXEC ? "mountNoExecute" :
                                         c == ARG_KILL_PROCESSES ? "killProcesses" :
                                c == ARG_ENFORCE_PASSWORD_POLICY ? "enforcePasswordPolicy" :
                                             c == ARG_AUTO_LOGIN ? "autoLogin" :
                                    c == ARG_PASSWORD_CHANGE_NOW ? "passwordChangeNow" :
                                                                   NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s boolean: %m", field);

                        r = sd_json_variant_set_field_boolean(&arg_identity_extra, field, r > 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case 'P':
                        r = sd_json_variant_set_field_boolean(&arg_identity_extra, "enforcePasswordPolicy", false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set enforcePasswordPolicy field: %m");

                        break;

                case ARG_DISK_SIZE:
                        if (isempty(optarg)) {
                                FOREACH_STRING(prop, "diskSize", "diskSizeRelative", "rebalanceWeight") {
                                        r = drop_from_identity(prop);
                                        if (r < 0)
                                                return r;
                                }

                                arg_disk_size = arg_disk_size_relative = UINT64_MAX;
                                break;
                        }

                        r = parse_permyriad(optarg);
                        if (r < 0) {
                                r = parse_disk_size(optarg, &arg_disk_size);
                                if (r < 0)
                                        return r;

                                r = drop_from_identity("diskSizeRelative");
                                if (r < 0)
                                        return r;

                                r = sd_json_variant_set_field_unsigned(&arg_identity_extra_this_machine, "diskSize", arg_disk_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set diskSize field: %m");

                                arg_disk_size_relative = UINT64_MAX;
                        } else {
                                /* Normalize to UINT32_MAX == 100% */
                                arg_disk_size_relative = UINT32_SCALE_FROM_PERMYRIAD(r);

                                r = drop_from_identity("diskSize");
                                if (r < 0)
                                        return r;

                                r = sd_json_variant_set_field_unsigned(&arg_identity_extra_this_machine, "diskSizeRelative", arg_disk_size_relative);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set diskSizeRelative field: %m");

                                arg_disk_size = UINT64_MAX;
                        }

                        /* Automatically turn off the rebalance logic if user configured a size explicitly */
                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra_this_machine, "rebalanceWeight", REBALANCE_WEIGHT_OFF);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set rebalanceWeight field: %m");

                        break;

                case ARG_ACCESS_MODE: {
                        mode_t mode;

                        if (isempty(optarg)) {
                                r = drop_from_identity("accessMode");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_mode(optarg, &mode);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Access mode '%s' not valid.", optarg);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, "accessMode", mode);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set access mode field: %m");

                        break;
                }

                case ARG_LUKS_DISCARD:
                        if (isempty(optarg)) {
                                r = drop_from_identity("luksDiscard");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --luks-discard= parameter: %s", optarg);

                        r = sd_json_variant_set_field_boolean(&arg_identity_extra, "luksDiscard", r);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set discard field: %m");

                        break;

                case ARG_LUKS_OFFLINE_DISCARD:
                        if (isempty(optarg)) {
                                r = drop_from_identity("luksOfflineDiscard");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --luks-offline-discard= parameter: %s", optarg);

                        r = sd_json_variant_set_field_boolean(&arg_identity_extra, "luksOfflineDiscard", r);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set offline discard field: %m");

                        break;

                case ARG_LUKS_VOLUME_KEY_SIZE:
                case ARG_LUKS_PBKDF_FORCE_ITERATIONS:
                case ARG_LUKS_PBKDF_PARALLEL_THREADS:
                case ARG_RATE_LIMIT_BURST: {
                        const char *field =
                                       c == ARG_LUKS_VOLUME_KEY_SIZE ? "luksVolumeKeySize" :
                                c == ARG_LUKS_PBKDF_FORCE_ITERATIONS ? "luksPbkdfForceIterations" :
                                c == ARG_LUKS_PBKDF_PARALLEL_THREADS ? "luksPbkdfParallelThreads" :
                                           c == ARG_RATE_LIMIT_BURST ? "rateLimitBurst" : NULL;
                        unsigned n;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                        }

                        r = safe_atou(optarg, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %s", field, optarg);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field, n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_LUKS_SECTOR_SIZE: {
                        uint64_t ss;

                        if (isempty(optarg)) {
                                r = drop_from_identity("luksSectorSize");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_sector_size(optarg, &ss);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, "luksSectorSize", ss);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set sector size field: %m");

                        break;
                }

                case ARG_UMASK: {
                        mode_t m;

                        if (isempty(optarg)) {
                                r = drop_from_identity("umask");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_mode(optarg, &m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse umask: %m");

                        r = sd_json_variant_set_field_integer(&arg_identity_extra, "umask", m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set umask field: %m");

                        break;
                }

                case ARG_SSH_AUTHORIZED_KEYS: {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        _cleanup_strv_free_ char **l = NULL, **add = NULL;

                        if (isempty(optarg)) {
                                r = drop_from_identity("sshAuthorizedKeys");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (optarg[0] == '@') {
                                _cleanup_fclose_ FILE *f = NULL;

                                /* If prefixed with '@' read from a file */

                                f = fopen(optarg+1, "re");
                                if (!f)
                                        return log_error_errno(errno, "Failed to open '%s': %m", optarg+1);

                                for (;;) {
                                        _cleanup_free_ char *line = NULL;

                                        r = read_line(f, LONG_LINE_MAX, &line);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to read from '%s': %m", optarg+1);
                                        if (r == 0)
                                                break;

                                        if (isempty(line))
                                                continue;

                                        if (line[0] == '#')
                                                continue;

                                        r = strv_consume(&add, TAKE_PTR(line));
                                        if (r < 0)
                                                return log_oom();
                                }
                        } else {
                                /* Otherwise, assume it's a literal key. Let's do some superficial checks
                                 * before accept it though. */

                                if (string_has_cc(optarg, NULL))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Authorized key contains control characters, refusing.");
                                if (optarg[0] == '#')
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified key is a comment?");

                                add = strv_new(optarg);
                                if (!add)
                                        return log_oom();
                        }

                        v = sd_json_variant_ref(sd_json_variant_by_key(arg_identity_extra_privileged, "sshAuthorizedKeys"));
                        if (v) {
                                r = sd_json_variant_strv(v, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse SSH authorized keys list: %m");
                        }

                        r = strv_extend_strv_consume(&l, TAKE_PTR(add), /* filter_duplicates = */ true);
                        if (r < 0)
                                return log_oom();

                        v = sd_json_variant_unref(v);

                        r = sd_json_variant_new_array_strv(&v, l);
                        if (r < 0)
                                return log_oom();

                        r = sd_json_variant_set_field(&arg_identity_extra_privileged, "sshAuthorizedKeys", v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set authorized keys: %m");

                        break;
                }

                case ARG_NOT_BEFORE:
                case ARG_NOT_AFTER:
                case 'e': {
                        const char *field;
                        usec_t n;

                        field =           c == ARG_NOT_BEFORE ? "notBeforeUSec" :
                                IN_SET(c, ARG_NOT_AFTER, 'e') ? "notAfterUSec" : NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        /* Note the minor discrepancy regarding -e parsing here: we support that for compat
                         * reasons, and in the original useradd(8) implementation it accepts dates in the
                         * format YYYY-MM-DD. Coincidentally, we accept dates formatted like that too, but
                         * with greater precision. */
                        r = parse_timestamp(optarg, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %m", field);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field, n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);
                        break;
                }

                case ARG_PASSWORD_CHANGE_MIN:
                case ARG_PASSWORD_CHANGE_MAX:
                case ARG_PASSWORD_CHANGE_WARN:
                case ARG_PASSWORD_CHANGE_INACTIVE: {
                        const char *field;
                        usec_t n;

                        field =      c == ARG_PASSWORD_CHANGE_MIN ? "passwordChangeMinUSec" :
                                     c == ARG_PASSWORD_CHANGE_MAX ? "passwordChangeMaxUSec" :
                                    c == ARG_PASSWORD_CHANGE_WARN ? "passwordChangeWarnUSec" :
                                c == ARG_PASSWORD_CHANGE_INACTIVE ? "passwordChangeInactiveUSec" :
                                                                    NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_sec(optarg, &n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %m", field);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field, n);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);
                        break;
                }

                case ARG_STORAGE:
                case ARG_FS_TYPE:
                case ARG_LUKS_CIPHER:
                case ARG_LUKS_CIPHER_MODE:
                case ARG_LUKS_PBKDF_TYPE:
                case ARG_LUKS_PBKDF_HASH_ALGORITHM: {

                        const char *field =
                                                  c == ARG_STORAGE ? "storage" :
                                                  c == ARG_FS_TYPE ? "fileSystemType" :
                                              c == ARG_LUKS_CIPHER ? "luksCipher" :
                                         c == ARG_LUKS_CIPHER_MODE ? "luksCipherMode" :
                                          c == ARG_LUKS_PBKDF_TYPE ? "luksPbkdfType" :
                                c == ARG_LUKS_PBKDF_HASH_ALGORITHM ? "luksPbkdfHashAlgorithm" : NULL;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        if (!string_is_safe(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Parameter for %s field not valid: %s", field, optarg);

                        r = sd_json_variant_set_field_string(
                                        IN_SET(c, ARG_STORAGE, ARG_FS_TYPE) ?
                                        &arg_identity_extra_this_machine :
                                        &arg_identity_extra, field, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_LUKS_PBKDF_TIME_COST:
                case ARG_RATE_LIMIT_INTERVAL:
                case ARG_STOP_DELAY: {
                        const char *field =
                                c == ARG_LUKS_PBKDF_TIME_COST ? "luksPbkdfTimeCostUSec" :
                                 c == ARG_RATE_LIMIT_INTERVAL ? "rateLimitIntervalUSec" :
                                          c == ARG_STOP_DELAY ? "stopDelayUSec" :
                                                                NULL;
                        usec_t t;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = parse_sec(optarg, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s field: %s", field, optarg);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field, t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case 'G': {
                        const char *p = optarg;

                        if (isempty(p)) {
                                r = drop_from_identity("memberOf");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        for (;;) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mo = NULL;
                                _cleanup_strv_free_ char **list = NULL;
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse group list: %m");
                                if (r == 0)
                                        break;

                                if (!valid_user_group_name(word, 0))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid group name %s.", word);

                                mo = sd_json_variant_ref(sd_json_variant_by_key(arg_identity_extra, "memberOf"));

                                r = sd_json_variant_strv(mo, &list);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse group list: %m");

                                r = strv_extend(&list, word);
                                if (r < 0)
                                        return log_oom();

                                strv_sort_uniq(list);

                                mo = sd_json_variant_unref(mo);
                                r = sd_json_variant_new_array_strv(&mo, list);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create group list JSON: %m");

                                r = sd_json_variant_set_field(&arg_identity_extra, "memberOf", mo);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update group list: %m");
                        }

                        break;
                }

                case ARG_TASKS_MAX: {
                        uint64_t u;

                        if (isempty(optarg)) {
                                r = drop_from_identity("tasksMax");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = safe_atou64(optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tasks-max= parameter: %s", optarg);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, "tasksMax", u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set tasksMax field: %m");

                        break;
                }

                case ARG_MEMORY_MAX:
                case ARG_MEMORY_HIGH:
                case ARG_LUKS_PBKDF_MEMORY_COST: {
                        const char *field =
                                            c == ARG_MEMORY_MAX ? "memoryMax" :
                                           c == ARG_MEMORY_HIGH ? "memoryHigh" :
                                c == ARG_LUKS_PBKDF_MEMORY_COST ? "luksPbkdfMemoryCost" : NULL;

                        uint64_t u;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = parse_size(optarg, 1024, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse %s parameter: %s", field, optarg);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra_this_machine, field, u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_CPU_WEIGHT:
                case ARG_IO_WEIGHT: {
                        const char *field = c == ARG_CPU_WEIGHT ? "cpuWeight" :
                                            c == ARG_IO_WEIGHT ? "ioWeight" : NULL;
                        uint64_t u;

                        assert(field);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = safe_atou64(optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --cpu-weight=/--io-weight= parameter: %s", optarg);

                        if (!CGROUP_WEIGHT_IS_OK(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Weight %" PRIu64 " is out of valid weight range.", u);

                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field, u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        break;
                }

                case ARG_PKCS11_TOKEN_URI:
                        if (streq(optarg, "list"))
                                return pkcs11_list_tokens();

                        /* If --pkcs11-token-uri= is specified we always drop everything old */
                        FOREACH_STRING(p, "pkcs11TokenUri", "pkcs11EncryptedKey") {
                                r = drop_from_identity(p);
                                if (r < 0)
                                        return r;
                        }

                        if (isempty(optarg)) {
                                arg_pkcs11_token_uri = strv_free(arg_pkcs11_token_uri);
                                break;
                        }

                        if (streq(optarg, "auto")) {
                                _cleanup_free_ char *found = NULL;

                                r = pkcs11_find_token_auto(&found);
                                if (r < 0)
                                        return r;
                                r = strv_consume(&arg_pkcs11_token_uri, TAKE_PTR(found));
                        } else {
                                if (!pkcs11_uri_valid(optarg))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid PKCS#11 URI: %s", optarg);

                                r = strv_extend(&arg_pkcs11_token_uri, optarg);
                        }
                        if (r < 0)
                                return r;

                        strv_uniq(arg_pkcs11_token_uri);
                        break;

                case ARG_FIDO2_CRED_ALG:
                        r = parse_fido2_algorithm(optarg, &arg_fido2_cred_alg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse COSE algorithm: %s", optarg);
                        break;

                case ARG_FIDO2_DEVICE:
                        if (streq(optarg, "list"))
                                return fido2_list_devices();

                        FOREACH_STRING(p, "fido2HmacCredential", "fido2HmacSalt") {
                                r = drop_from_identity(p);
                                if (r < 0)
                                        return r;
                        }

                        if (isempty(optarg)) {
                                arg_fido2_device = strv_free(arg_fido2_device);
                                break;
                        }

                        if (streq(optarg, "auto")) {
                                _cleanup_free_ char *found = NULL;

                                r = fido2_find_device_auto(&found);
                                if (r < 0)
                                        return r;

                                r = strv_consume(&arg_fido2_device, TAKE_PTR(found));
                        } else
                                r = strv_extend(&arg_fido2_device, optarg);
                        if (r < 0)
                                return r;

                        strv_uniq(arg_fido2_device);
                        break;

                case ARG_FIDO2_WITH_PIN:
                        r = parse_boolean_argument("--fido2-with-client-pin=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_PIN, r);
                        break;

                case ARG_FIDO2_WITH_UP:
                        r = parse_boolean_argument("--fido2-with-user-presence=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UP, r);
                        break;

                case ARG_FIDO2_WITH_UV:
                        r = parse_boolean_argument("--fido2-with-user-verification=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UV, r);
                        break;

                case ARG_RECOVERY_KEY:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --recovery-key= argument: %s", optarg);

                        arg_recovery_key = r;

                        FOREACH_STRING(p, "recoveryKey", "recoveryKeyType") {
                                r = drop_from_identity(p);
                                if (r < 0)
                                        return r;
                        }

                        break;

                case ARG_AUTO_RESIZE_MODE:
                        if (isempty(optarg)) {
                                r = drop_from_identity("autoResizeMode");
                                if (r < 0)
                                        return r;

                                break;
                        }

                        r = auto_resize_mode_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --auto-resize-mode= argument: %s", optarg);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "autoResizeMode", auto_resize_mode_to_string(r));
                        if (r < 0)
                                return log_error_errno(r, "Failed to set autoResizeMode field: %m");

                        break;

                case ARG_REBALANCE_WEIGHT: {
                        uint64_t u;

                        if (isempty(optarg)) {
                                r = drop_from_identity("rebalanceWeight");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        if (streq(optarg, "off"))
                                u = REBALANCE_WEIGHT_OFF;
                        else {
                                r = safe_atou64(optarg, &u);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --rebalance-weight= argument: %s", optarg);

                                if (u < REBALANCE_WEIGHT_MIN || u > REBALANCE_WEIGHT_MAX)
                                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Rebalancing weight out of valid range %" PRIu64 "%s%" PRIu64 ": %s",
                                                               REBALANCE_WEIGHT_MIN, special_glyph(SPECIAL_GLYPH_ELLIPSIS), REBALANCE_WEIGHT_MAX, optarg);
                        }

                        /* Drop from per machine stuff and everywhere */
                        r = drop_from_identity("rebalanceWeight");
                        if (r < 0)
                                return r;

                        /* Add to main identity */
                        r = sd_json_variant_set_field_unsigned(&arg_identity_extra, "rebalanceWeight", u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set rebalanceWeight field: %m");

                        break;
                }

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case 'E':
                        if (arg_export_format == EXPORT_FORMAT_FULL)
                                arg_export_format = EXPORT_FORMAT_STRIPPED;
                        else if (arg_export_format == EXPORT_FORMAT_STRIPPED)
                                arg_export_format = EXPORT_FORMAT_MINIMAL;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specifying -E more than twice is not supported.");

                        arg_json_format_flags &= ~SD_JSON_FORMAT_OFF;
                        if (arg_json_format_flags == 0)
                                arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_EXPORT_FORMAT:
                        if (streq(optarg, "full"))
                                arg_export_format = EXPORT_FORMAT_FULL;
                        else if (streq(optarg, "stripped"))
                                arg_export_format = EXPORT_FORMAT_STRIPPED;
                        else if (streq(optarg, "minimal"))
                                arg_export_format = EXPORT_FORMAT_MINIMAL;
                        else if (streq(optarg, "help")) {
                                puts("full\n"
                                     "stripped\n"
                                     "minimal");
                                return 0;
                        }

                        break;

                case ARG_AND_RESIZE:
                        arg_and_resize = true;
                        break;

                case ARG_AND_CHANGE_PASSWORD:
                        arg_and_change_password = true;
                        break;

                case ARG_DROP_CACHES: {
                        if (isempty(optarg)) {
                                r = drop_from_identity("dropCaches");
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = parse_boolean_argument("--drop-caches=", optarg, NULL);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_set_field_boolean(&arg_identity_extra, "dropCaches", r);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set drop caches field: %m");

                        break;
                }

                case ARG_CAPABILITY_AMBIENT_SET:
                case ARG_CAPABILITY_BOUNDING_SET: {
                        _cleanup_strv_free_ char **l = NULL;
                        bool subtract = false;
                        uint64_t parsed, *which, updated;
                        const char *p, *field;

                        if (c == ARG_CAPABILITY_AMBIENT_SET) {
                                which = &arg_capability_ambient_set;
                                field = "capabilityAmbientSet";
                        } else {
                                assert(c == ARG_CAPABILITY_BOUNDING_SET);
                                which = &arg_capability_bounding_set;
                                field = "capabilityBoundingSet";
                        }

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;

                                *which = UINT64_MAX;
                                break;
                        }

                        p = optarg;
                        if (*p == '~') {
                                subtract = true;
                                p++;
                        }

                        r = capability_set_from_string(p, &parsed);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid capabilities in capability string '%s'.", p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse capability string '%s': %m", p);

                        if (*which == UINT64_MAX)
                                updated = subtract ? all_capabilities() & ~parsed : parsed;
                        else if (subtract)
                                updated = *which & ~parsed;
                        else
                                updated = *which | parsed;

                        if (capability_set_to_strv(updated, &l) < 0)
                                return log_oom();

                        r = sd_json_variant_set_field_strv(&arg_identity_extra, field, l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", field);

                        *which = updated;
                        break;
                }

                case ARG_PROMPT_NEW_USER:
                        arg_prompt_new_user = true;
                        break;

                case 'b':
                case ARG_AVATAR:
                case ARG_LOGIN_BACKGROUND: {
                        _cleanup_close_ int fd = -EBADF;
                        _cleanup_free_ char *path = NULL, *filename = NULL;

                        if (c == 'b') {
                                char *eq;

                                if (isempty(optarg)) { /* --blob= deletes everything, including existing blob dirs */
                                        hashmap_clear(arg_blob_files);
                                        arg_blob_dir = mfree(arg_blob_dir);
                                        arg_blob_clear = true;
                                        break;
                                }

                                eq = strrchr(optarg, '=');
                                if (!eq) { /* --blob=/some/path replaces the blob dir */
                                        r = parse_path_argument(optarg, false, &arg_blob_dir);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse path %s: %m", optarg);
                                        break;
                                }

                                /* --blob=filename=/some/path replaces the file "filename" with /some/path */
                                filename = strndup(optarg, eq - optarg);
                                if (!filename)
                                        return log_oom();

                                if (isempty(filename))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't parse blob file assignment: %s", optarg);
                                if (!suitable_blob_filename(filename))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid blob filename: %s", filename);

                                r = parse_path_argument(eq + 1, false, &path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse path %s: %m", eq + 1);
                        } else {
                                const char *well_known_filename =
                                                  c == ARG_AVATAR ? "avatar" :
                                        c == ARG_LOGIN_BACKGROUND ? "login-background" :
                                                                    NULL;
                                assert(well_known_filename);

                                filename = strdup(well_known_filename);
                                if (!filename)
                                        return log_oom();

                                r = parse_path_argument(optarg, false, &path);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse path %s: %m", optarg);
                        }

                        if (path) {
                                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                                if (fd < 0)
                                        return log_error_errno(errno, "Failed to open %s: %m", path);

                                if (fd_verify_regular(fd) < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Provided blob is not a regular file: %s", path);
                        } else
                                fd = -EBADF; /* Delete the file */

                        r = hashmap_ensure_put(&arg_blob_files, &blob_fd_hash_ops, filename, FD_TO_PTR(fd));
                        if (r < 0)
                                return log_error_errno(r, "Failed to map %s to %s in blob directory: %m", path, filename);
                        TAKE_PTR(filename); /* hashmap takes ownership */
                        TAKE_FD(fd);

                        break;
                }

                case ARG_TMP_LIMIT:
                case ARG_DEV_SHM_LIMIT: {
                        const char *field =
                                    c == ARG_TMP_LIMIT ? "tmpLimit" :
                                c == ARG_DEV_SHM_LIMIT ? "devShmLimit" : NULL;
                        const char *field_scale =
                                    c == ARG_TMP_LIMIT ? "tmpLimitScale" :
                                c == ARG_DEV_SHM_LIMIT ? "devShmLimitScale" : NULL;

                        assert(field);
                        assert(field_scale);

                        if (isempty(optarg)) {
                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                                r = drop_from_identity(field_scale);
                                if (r < 0)
                                        return r;
                                break;
                        }

                        r = parse_permyriad(optarg);
                        if (r < 0) {
                                uint64_t u;

                                r = parse_size(optarg, 1024, &u);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse %s/%s parameter: %s", field, field_scale, optarg);

                                r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field, u);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set %s field: %m", field);

                                r = drop_from_identity(field_scale);
                                if (r < 0)
                                        return r;
                        } else {
                                r = sd_json_variant_set_field_unsigned(&arg_identity_extra, field_scale, UINT32_SCALE_FROM_PERMYRIAD(r));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set %s field: %m", field_scale);

                                r = drop_from_identity(field);
                                if (r < 0)
                                        return r;
                        }

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (!strv_isempty(arg_pkcs11_token_uri) || !strv_isempty(arg_fido2_device))
                arg_and_change_password = true;

        if (arg_disk_size != UINT64_MAX || arg_disk_size_relative != UINT64_MAX)
                arg_and_resize = true;

        if (!strv_isempty(arg_languages)) {
                char **additional;

                r = sd_json_variant_set_field_string(&arg_identity_extra, "preferredLanguage", arg_languages[0]);
                if (r < 0)
                        return log_error_errno(r, "Failed to update preferred language: %m");

                additional = strv_skip(arg_languages, 1);
                if (!strv_isempty(additional)) {
                        r = sd_json_variant_set_field_strv(&arg_identity_extra, "additionalLanguages", additional);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update additional language list: %m");
                } else {
                        r = drop_from_identity("additionalLanguages");
                        if (r < 0)
                                return r;
                }
        }

        return 1;
}

static int redirect_bus_mgr(void) {
        const char *suffix;

        /* Talk to a different service if that's requested. (The same env var is also understood by homed, so
         * that it is relatively easily possible to invoke a second instance of homed for debug purposes and
         * have homectl talk to it, without colliding with the host version. This is handy when operating
         * from a homed-managed account.) */

        suffix = getenv("SYSTEMD_HOME_DEBUG_SUFFIX");
        if (suffix) {
                static BusLocator locator = {
                        .path = "/org/freedesktop/home1",
                        .interface = "org.freedesktop.home1.Manager",
                };

                /* Yes, we leak this memory, but there's little point to collect this, given that we only do
                 * this in a debug environment, do it only once, and the string shall live for out entire
                 * process runtime. */

                locator.destination = strjoin("org.freedesktop.home1.", suffix);
                if (!locator.destination)
                        return log_oom();

                bus_mgr = &locator;
        } else
                bus_mgr = bus_home_mgr;

        return 0;
}

static bool is_fallback_shell(const char *p) {
        const char *q;

        if (!p)
                return false;

        if (p[0] == '-') {
                /* Skip over login shell dash */
                p++;

                if (streq(p, "ystemd-home-fallback-shell")) /* maybe the dash was used to override the binary name? */
                        return true;
        }

        q = strrchr(p, '/'); /* Skip over path */
        if (q)
                p = q + 1;

        return streq(p, "systemd-home-fallback-shell");
}

static int fallback_shell(int argc, char *argv[]) {
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL, *hr = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *argv0 = NULL;
        const char *json, *hd, *shell;
        int r, incomplete;

        /* So here's the deal: if users log into a system via ssh, and their homed-managed home directory
         * wasn't activated yet, SSH will permit the access but the home directory isn't actually available
         * yet. SSH doesn't allow us to ask authentication questions from the PAM session stack, and doesn't
         * run the PAM authentication stack (because it authenticates via its own key management, after
         * all). So here's our way to support this: homectl can be invoked as a multi-call binary under the
         * name "systemd-home-fallback-shell". If so, it will chainload a login shell, but first try to
         * unlock the home directory of the user it is invoked as. systemd-homed will then override the shell
         * listed in user records whose home directory is not activated yet with this pseudo-shell. Net
         * effect: one SSH auth succeeds this pseudo shell gets invoked, which will unlock the homedir
         * (possibly asking for a passphrase) and then chainload the regular shell. Once the login is
         * complete the user record will look like any other. */

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        for (unsigned n_tries = 0;; n_tries++) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                if (n_tries >= 5)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to activate home dir, even after %u tries.", n_tries);

                /* Let's start by checking if this all is even necessary, i.e. if the useFallback boolean field is actually set. */
                r = bus_call_method(bus, bus_mgr, "GetUserRecordByName", &error, &reply, "s", NULL); /* empty user string means: our calling user */
                if (r < 0)
                        return log_error_errno(r, "Failed to inspect home: %s", bus_error_message(&error, r));

                r = sd_bus_message_read(reply, "sbo", &json, NULL, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON identity: %m");

                hr = user_record_new();
                if (!hr)
                        return log_oom();

                r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_LOG|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        return r;

                if (!hr->use_fallback) /* Nice! We are done, fallback logic not necessary */
                        break;

                if (!secret) {
                        r = acquire_passed_secrets(hr->user_name, &secret);
                        if (r < 0)
                                return r;
                }

                for (;;) {
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                        r = bus_message_new_method_call(bus, &m, bus_mgr, "ActivateHomeIfReferenced");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "s", NULL); /* empty user string means: our calling user */
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_message_append_secret(m, secret);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                        if (r < 0) {
                                if (sd_bus_error_has_name(&error, BUS_ERROR_HOME_NOT_REFERENCED))
                                        return log_error_errno(r, "Called without reference on home taken, can't operate.");

                                r = handle_generic_user_record_error(hr->user_name, secret, &error, r, false);
                                if (r < 0)
                                        return r;

                                sd_bus_error_free(&error);
                        } else
                                break;
                }

                /* Try again */
                hr = user_record_unref(hr);
        }

        incomplete = getenv_bool("XDG_SESSION_INCOMPLETE"); /* pam_systemd_home reports this state via an environment variable to us. */
        if (incomplete < 0 && incomplete != -ENXIO)
                return log_error_errno(incomplete, "Failed to parse $XDG_SESSION_INCOMPLETE environment variable: %m");
        if (incomplete > 0) {
                /* We are still in an "incomplete" session here. Now upgrade it to a full one. This will make logind
                 * start the user@.service instance for us. */
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.login1",
                                "/org/freedesktop/login1/session/self",
                                "org.freedesktop.login1.Session",
                                "SetClass",
                                &error,
                                /* ret_reply= */ NULL,
                                "s",
                                "user");
                if (r < 0)
                        return log_error_errno(r, "Failed to upgrade session: %s", bus_error_message(&error, r));

                if (setenv("XDG_SESSION_CLASS", "user", /* overwrite= */ true) < 0) /* Update the XDG_SESSION_CLASS environment variable to match the above */
                        return log_error_errno(errno, "Failed to set $XDG_SESSION_CLASS: %m");

                if (unsetenv("XDG_SESSION_INCOMPLETE") < 0) /* Unset the 'incomplete' env var */
                        return log_error_errno(errno, "Failed to unset $XDG_SESSION_INCOMPLETE: %m");
        }

        /* We are going to invoke execv() soon. Let's be extra accurate and flush/close our bus connection
         * first, just to make sure anything queued is flushed out (though there shouldn't be anything) */
        bus = sd_bus_flush_close_unref(bus);

        assert(!hr->use_fallback);
        assert_se(shell = user_record_shell(hr));
        assert_se(hd = user_record_home_directory(hr));

        /* Extra protection: avoid loops */
        if (is_fallback_shell(shell))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Primary shell of '%s' is fallback shell, refusing loop.", hr->user_name);

        if (chdir(hd) < 0)
                return log_error_errno(errno, "Failed to change directory to home directory '%s': %m", hd);

        if (setenv("SHELL", shell, /* overwrite= */ true) < 0)
                return log_error_errno(errno, "Failed to set $SHELL: %m");

        if (setenv("HOME", hd, /* overwrite= */ true) < 0)
                return log_error_errno(errno, "Failed to set $HOME: %m");

        /* Paranoia: in case the client passed some passwords to us to help us unlock, unlock things now */
        FOREACH_STRING(ue, "PASSWORD", "NEWPASSWORD", "PIN")
                if (unsetenv(ue) < 0)
                        return log_error_errno(errno, "Failed to unset $%s: %m", ue);

        r = path_extract_filename(shell, &argv0);
        if (r < 0)
                return log_error_errno(r, "Unable to extract file name from '%s': %m", shell);
        if (r == O_DIRECTORY)
                return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Shell '%s' is a path to a directory, refusing.", shell);

        /* Invoke this as login shell, by setting argv[0][0] to '-' (unless we ourselves weren't called as login shell) */
        if (!argv || isempty(argv[0]) || argv[0][0] == '-') {
                _cleanup_free_ char *prefixed = strjoin("-", argv0);
                if (!prefixed)
                        return log_oom();

                free_and_replace(argv0, prefixed);
        }

        l = strv_new(argv0);
        if (!l)
                return log_oom();

        if (strv_extend_strv(&l, strv_skip(argv, 1), /* filter_duplicates= */ false) < 0)
                return log_oom();

        execv(shell, l);
        return log_error_errno(errno, "Failed to execute shell '%s': %m", shell);
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",           VERB_ANY, VERB_ANY, 0,            help                 },
                { "list",           VERB_ANY, 1,        VERB_DEFAULT, list_homes           },
                { "activate",       2,        VERB_ANY, 0,            activate_home        },
                { "deactivate",     2,        VERB_ANY, 0,            deactivate_home      },
                { "inspect",        VERB_ANY, VERB_ANY, 0,            inspect_home         },
                { "authenticate",   VERB_ANY, VERB_ANY, 0,            authenticate_home    },
                { "create",         VERB_ANY, 2,        0,            create_home          },
                { "remove",         2,        VERB_ANY, 0,            remove_home          },
                { "update",         VERB_ANY, 2,        0,            update_home          },
                { "passwd",         VERB_ANY, 2,        0,            passwd_home          },
                { "resize",         2,        3,        0,            resize_home          },
                { "lock",           2,        VERB_ANY, 0,            lock_home            },
                { "unlock",         2,        VERB_ANY, 0,            unlock_home          },
                { "with",           2,        VERB_ANY, 0,            with_home            },
                { "lock-all",       VERB_ANY, 1,        0,            lock_all_homes       },
                { "deactivate-all", VERB_ANY, 1,        0,            deactivate_all_homes },
                { "rebalance",      VERB_ANY, 1,        0,            rebalance            },
                { "firstboot",      VERB_ANY, 1,        0,            verb_firstboot       },
                {}
        };

        int r;

        log_setup();

        r = redirect_bus_mgr();
        if (r < 0)
                return r;

        if (is_fallback_shell(argv[0]))
                return fallback_shell(argc, argv);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
