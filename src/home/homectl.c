/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-varlink.h"

#include "ask-password-api.h"
#include "bitfield.h"
#include "build.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "capability-list.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "creds-util.h"
#include "crypto-util.h"
#include "dirent-util.h"
#include "dns-domain.h"
#include "env-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "help-util.h"
#include "hexdecoct.h"
#include "home-util.h"
#include "homectl-fido2.h"
#include "homectl-pkcs11.h"
#include "homectl-prompts.h"
#include "homectl-recovery-key.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "password-quality-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "pidref.h"
#include "pkcs11-util.h"
#include "plymouth-util.h"
#include "polkit-agent.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "prompt-util.h"
#include "recurse-dir.h"
#include "rlimit-util.h"
#include "runtime-scope.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "uid-classification.h"
#include "user-record.h"
#include "user-record-password-quality.h"
#include "user-record-show.h"
#include "user-record-util.h"
#include "user-util.h"
#include "userdb.h"
#include "verbs.h"

typedef enum {
        EXPORT_FORMAT_FULL,          /* export the full record */
        EXPORT_FORMAT_STRIPPED,      /* strip "state" + "binding", but leave signature in place */
        EXPORT_FORMAT_MINIMAL,       /* also strip signature */
        _EXPORT_FORMAT_MAX,
        _EXPORT_FORMAT_INVALID = -EINVAL,
} ExportFormat;

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
static sd_json_variant *arg_identity_extra_other_machines = NULL;
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
static ExportFormat arg_export_format = EXPORT_FORMAT_FULL;
static uint64_t arg_capability_bounding_set = CAP_MASK_UNSET;
static uint64_t arg_capability_ambient_set = CAP_MASK_UNSET;
static char *arg_blob_dir = NULL;
static bool arg_blob_clear = false;
static Hashmap *arg_blob_files = NULL;
static char *arg_key_name = NULL;
static bool arg_dry_run = false;
static bool arg_seize = true;
static bool arg_prompt_new_user = false;
static bool arg_prompt_shell = true;
static bool arg_prompt_groups = true;
static bool arg_chrome = true;
static bool arg_mute_console = false;

STATIC_DESTRUCTOR_REGISTER(arg_identity_extra, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_this_machine, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_other_machines, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_privileged, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_extra_rlimits, sd_json_variant_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_identity_filter, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_identity_filter_rlimits, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_pkcs11_token_uri, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_fido2_device, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_blob_dir, freep);
STATIC_DESTRUCTOR_REGISTER(arg_blob_files, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(arg_key_name, freep);

static const BusLocator *bus_mgr;

static const char *export_format_table[_EXPORT_FORMAT_MAX] = {
        [EXPORT_FORMAT_FULL]     = "full",
        [EXPORT_FORMAT_STRIPPED] = "stripped",
        [EXPORT_FORMAT_MINIMAL]  = "minimal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(export_format, ExportFormat);

static bool identity_properties_specified(void) {
        return
                arg_identity ||
                !sd_json_variant_is_blank_object(arg_identity_extra) ||
                !sd_json_variant_is_blank_object(arg_identity_extra_privileged) ||
                !sd_json_variant_is_blank_object(arg_identity_extra_this_machine) ||
                !sd_json_variant_is_blank_object(arg_identity_extra_other_machines) ||
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

VERB_GROUP("Basic User Manipulation Commands");
VERB(verb_list_homes, "list", /* argspec= */ NULL, VERB_ANY, 1, VERB_DEFAULT,
     "List home areas");
static int verb_list_homes(int argc, char *argv[], uintptr_t _data, void *userdata) {
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
                bool emphasize_current_password,
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

        if (asprintf(&question, emphasize_current_password ?
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
                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

                r = user_record_set_pkcs11_protected_authentication_path_permitted(hr, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to set PKCS#11 protected authentication path permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_USER_PRESENCE_NEEDED)) {

                log_notice("%s%sPlease confirm presence on security token.",
                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

                r = user_record_set_fido2_user_presence_permitted(hr, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to set FIDO2 user presence permitted flag: %m");

        } else if (sd_bus_error_has_name(error, BUS_ERROR_TOKEN_USER_VERIFICATION_NEEDED)) {

                log_notice("%s%sPlease verify user on security token.",
                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
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
                        /* emphasize_current_password= */ false,
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

static int inspect_home(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        const char *json;
        int incomplete;
        uid_t uid;
        int r;

        r = parse_uid(name, &uid);
        if (r < 0)
                r = bus_call_method(bus, bus_mgr, "GetUserRecordByName", &error, &reply, "s", name);
        else
                r = bus_call_method(bus, bus_mgr, "GetUserRecordByUID", &error, &reply, "u", (uint32_t) uid);
        if (r < 0)
                return log_error_errno(r, "Failed to inspect home: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "sbo", &json, &incomplete, NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE|SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON identity: %m");

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_LOG|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        hr->incomplete = incomplete;
        dump_home_record(hr);
        return 0;
}

VERB(verb_inspect_homes, "inspect", "USER…", VERB_ANY, VERB_ANY, 0,
     "Inspect a home area");
static int verb_inspect_homes(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        char **args = strv_skip(argv, 1);
        if (args) {
                STRV_FOREACH(arg, args)
                        RET_GATHER(r, inspect_home(bus, *arg));
                return r;
        } else {
                _cleanup_free_ char *myself = getusername_malloc();
                if (!myself)
                        return log_oom();

                return inspect_home(bus, myself);
        }
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

        if (arg_identity_extra_this_machine || arg_identity_extra_other_machines || !strv_isempty(arg_identity_filter)) {
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
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *npm = NULL, *positive = NULL, *negative = NULL;
                        _cleanup_free_ sd_json_variant **array = NULL;
                        sd_json_variant *z;
                        size_t i = 0;

                        if (!sd_json_variant_is_array(per_machine))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "perMachine field is not an array, refusing.");

                        array = new(sd_json_variant*, sd_json_variant_elements(per_machine) + 2);
                        if (!array)
                                return log_oom();

                        JSON_VARIANT_ARRAY_FOREACH(z, per_machine) {
                                sd_json_variant *u;

                                if (!sd_json_variant_is_object(z))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "perMachine entry is not an object, refusing.");

                                array[i++] = z;

                                u = sd_json_variant_by_key(z, "matchMachineId");
                                if (u && sd_json_variant_equal(u, mmid))
                                        r = sd_json_variant_merge_object(&positive, z);
                                else {
                                        u = sd_json_variant_by_key(z, "matchNotMachineId");
                                        if (!u || !sd_json_variant_equal(u, mmid))
                                                continue;

                                        r = sd_json_variant_merge_object(&negative, z);
                                }
                                if (r < 0)
                                        return log_error_errno(r, "Failed to merge perMachine entry: %m");

                                i--;
                        }

                        r = sd_json_variant_filter(&positive, arg_identity_filter);
                        if (r < 0)
                                return log_error_errno(r, "Failed to filter perMachine: %m");

                        r = sd_json_variant_filter(&negative, arg_identity_filter);
                        if (r < 0)
                                return log_error_errno(r, "Failed to filter perMachine: %m");

                        r = sd_json_variant_merge_object(&positive, arg_identity_extra_this_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to merge in perMachine fields: %m");

                        r = sd_json_variant_merge_object(&negative, arg_identity_extra_other_machines);
                        if (r < 0)
                                return log_error_errno(r, "Failed to merge in perMachine fields: %m");

                        if (arg_identity_filter_rlimits || arg_identity_extra_rlimits) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *rlv = NULL;

                                rlv = sd_json_variant_ref(sd_json_variant_by_key(positive, "resourceLimits"));

                                r = sd_json_variant_filter(&rlv, arg_identity_filter_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to filter resource limits: %m");

                                r = sd_json_variant_merge_object(&rlv, arg_identity_extra_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set resource limits: %m");

                                if (sd_json_variant_is_blank_object(rlv)) {
                                        r = sd_json_variant_filter(&positive, STRV_MAKE("resourceLimits"));
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to drop resource limits field from identity: %m");
                                } else {
                                        r = sd_json_variant_set_field(&positive, "resourceLimits", rlv);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to update resource limits of identity: %m");
                                }
                        }

                        if (!sd_json_variant_is_blank_object(positive)) {
                                r = sd_json_variant_set_field(&positive, "matchMachineId", mmid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set matchMachineId field: %m");

                                array[i++] = positive;
                        }

                        if (!sd_json_variant_is_blank_object(negative)) {
                                r = sd_json_variant_set_field(&negative, "matchNotMachineId", mmid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set matchNotMachineId field: %m");

                                array[i++] = negative;
                        }

                        r = sd_json_variant_new_array(&npm, array, i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate new perMachine array: %m");

                        json_variant_unref_and_replace(per_machine, npm);
                } else {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *positive = sd_json_variant_ref(arg_identity_extra_this_machine),
                                *negative = sd_json_variant_ref(arg_identity_extra_other_machines);

                        if (arg_identity_extra_rlimits) {
                                r = sd_json_variant_set_field(&positive, "resourceLimits", arg_identity_extra_rlimits);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to update resource limits of identity: %m");
                        }

                        if (positive) {
                                r = sd_json_variant_set_field(&positive, "matchMachineId", mmid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set matchMachineId field: %m");

                                r = sd_json_variant_append_array(&per_machine, positive);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to append to perMachine array: %m");
                        }

                        if (negative) {
                                r = sd_json_variant_set_field(&negative, "matchNotMachineId", mmid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to set matchNotMachineId field: %m");

                                r = sd_json_variant_append_array(&per_machine, negative);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to append to perMachine array: %m");
                        }
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

        return json_variant_unref_and_replace(*_v, v);
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
                unsigned line = 0, column = 0;

                if (input)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Two identity records specified, refusing.");

                r = sd_json_parse_file(
                                streq(arg_identity, "-") ? stdin : NULL,
                                streq(arg_identity, "-") ? "<stdin>" : arg_identity,
                                SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SENSITIVE,
                                &v,
                                &line,
                                &column);
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
                        (arg_seize ? USER_RECORD_STRIP_SIGNATURE : USER_RECORD_ALLOW_SIGNATURE) |
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

                r = user_record_set_password(hr, STRV_MAKE(envpw), /* prepend= */ true);
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

                        r = user_record_set_password(hr, first, /* prepend= */ true);
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

static int create_home_common(sd_json_variant *input, bool show_enforce_password_policy_hint) {
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
                        r = acquire_new_password(hr->user_name, hr, /* suggest= */ true, &new_password);
                        if (r < 0)
                                return r;

                        r = user_record_make_hashed_password(hr, STRV_MAKE(new_password), /* extend= */ false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to hash password: %m");
                } else {
                        /* There's a hash password set in the record, acquire the unhashed version of it. */
                        r = acquire_existing_password(
                                        hr->user_name,
                                        hr,
                                        /* emphasize_current_password= */ false,
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

        if (arg_dry_run) {
                sd_json_variant_dump(hr->json, SD_JSON_FORMAT_COLOR_AUTO|SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_NEWLINE, stderr, /* prefix= */ NULL);
                return 0;
        }

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                _cleanup_(erase_and_freep) char *formatted = NULL;

                r = sd_json_variant_format(hr->json, /* flags= */ 0, &formatted);
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
                                if (show_enforce_password_policy_hint)
                                        log_info("(Use --enforce-password-policy=no to turn off password quality checks for this account.)");

                                r = acquire_new_password(hr->user_name, hr, /* suggest= */ false, &new_password);
                                if (r < 0)
                                        return r;

                                r = user_record_make_hashed_password(hr, STRV_MAKE(new_password), /* extend= */ false);
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

VERB(verb_create_home, "create", "USER", VERB_ANY, 2, 0,
     "Create a home area");
static int verb_create_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        if (argc >= 2) {
                /* If a username was specified, use it */

                if (valid_user_group_name(argv[1], /* flags= */ 0))
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

        return create_home_common(/* input= */ NULL, /* show_enforce_password_policy_hint= */ true);
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
                unsigned line = 0, column = 0;
                sd_json_variant *un;

                r = sd_json_parse_file(
                                streq(arg_identity, "-") ? stdin : NULL,
                                streq(arg_identity, "-") ? "<stdin>" : arg_identity,
                                SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SENSITIVE,
                                &json,
                                &line,
                                &column);
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

                r = sd_json_parse(
                                text,
                                SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SENSITIVE,
                                &json,
                                /* reterr_line= */ NULL,
                                /* reterr_column= */ NULL);
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

        if (arg_recovery_key) {
                r = identity_add_recovery_key(&json);
                if (r < 0)
                        return r;
        }

        /* If the user supplied a full record, then add in lastChange, but do not override. Otherwise always
         * override. */
        r = update_last_change(&json, arg_pkcs11_token_uri || arg_fido2_device || arg_recovery_key, !arg_identity);
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

VERB(verb_update_home, "update", "USER", VERB_ANY, 2, 0,
     "Update a home area");
static int verb_update_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

        bool and_change_password = !strv_isempty(arg_pkcs11_token_uri) || !strv_isempty(arg_fido2_device);
        bool and_resize = arg_disk_size != UINT64_MAX || arg_disk_size_relative != UINT64_MAX;

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

        if (arg_dry_run) {
                sd_json_variant_dump(hr->json, SD_JSON_FORMAT_COLOR_AUTO|SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_NEWLINE, stderr, /* prefix= */ NULL);
                return 0;
        }

        /* If we do multiple operations, let's output things more verbosely, since otherwise the repeated
         * authentication might be confusing. */

        if (and_resize || and_change_password)
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

                r = sd_json_variant_format(hr->json, /* flags= */ 0, &formatted);
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
                        if (and_change_password &&
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

        if (and_resize)
                log_info("Resizing home.");

        (void) home_record_reset_human_interaction_permission(hr);

        /* Also sync down disk size to underlying LUKS/fscrypt/quota */
        while (and_resize) {
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
                        if (and_change_password &&
                            sd_bus_error_has_name(&error, BUS_ERROR_BAD_PASSWORD_AND_NO_TOKEN))
                                return log_error_errno(r, "Security token not inserted, refusing.");

                        r = handle_generic_user_record_error(hr->user_name, hr, &error, r, false);
                        if (r < 0)
                                return r;
                } else
                        break;
        }

        if (and_change_password)
                log_info("Synchronizing passwords and encryption keys.");

        (void) home_record_reset_human_interaction_permission(hr);

        /* Also sync down passwords to underlying LUKS/fscrypt */
        while (and_change_password) {
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

VERB(verb_passwd_home, "passwd", "USER", VERB_ANY, 2, 0,
     "Change password of a home area");
static int verb_passwd_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(user_record_unrefp) UserRecord *old_secret = NULL, *new_secret = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buffer = NULL;
        const char *username;
        int r;

        if (arg_pkcs11_token_uri)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "To change the PKCS#11 security token use 'homectl update --pkcs11-token-uri=%s'.",
                                       glyph(GLYPH_ELLIPSIS));
        if (arg_fido2_device)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "To change the FIDO2 security token use 'homectl update --fido2-device=%s'.",
                                       glyph(GLYPH_ELLIPSIS));
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

        r = acquire_new_password(username, new_secret, /* suggest= */ true, NULL);
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

                                r = acquire_new_password(username, new_secret, /* suggest= */ false, NULL);

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

VERB(verb_resize_home, "resize", "USER SIZE", 2, 3, 0,
     "Resize a home area");
static int verb_resize_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_remove_home, "remove", "USER…", 2, VERB_ANY, 0,
     "Remove a home area");
static int verb_remove_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB_GROUP("Advanced User Manipulation Commands");
VERB(verb_activate_home, "activate", "USER…", 2, VERB_ANY, 0,
     "Activate a home area");
static int verb_activate_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_deactivate_home, "deactivate", "USER…", 2, VERB_ANY, 0,
     "Deactivate a home area");
static int verb_deactivate_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB_NOARG(verb_deactivate_all_homes, "deactivate-all",
           "Deactivate all active home areas");
static int verb_deactivate_all_homes(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_with_home, "with", "USER [COMMAND…]", 2, VERB_ANY, 0,
     "Run shell or command with access to a home area");
static int verb_with_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        _cleanup_close_ int acquired_fd = -EBADF;
        _cleanup_strv_free_ char **cmdline  = NULL;
        const char *home;
        int r, ret;

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

                r = sd_bus_message_append(m, "b", /* please_suspend= */ getenv_bool("SYSTEMD_PLEASE_SUSPEND_HOME") > 0);
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

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        "(with)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REOPEN_LOG,
                        &pidref);
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

        ret = pidref_wait_for_terminate_and_check(cmdline[0], &pidref, WAIT_LOG_ABNORMAL);

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

static int authenticate_home(sd_bus *bus, const char *name) {
        _cleanup_(user_record_unrefp) UserRecord *secret = NULL;
        int r;

        r = acquire_passed_secrets(name, &secret);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = bus_message_new_method_call(bus, &m, bus_mgr, "AuthenticateHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", name);
                if (r < 0)
                        return bus_log_create_error(r);

                r = bus_message_append_secret(m, secret);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        r = handle_generic_user_record_error(name, secret, &error, r, false);
                        if (r >= 0)
                                continue;
                }
                return r;
        }
}

VERB(verb_authenticate_homes, "authenticate", "USER…", VERB_ANY, VERB_ANY, 0,
     "Authenticate a home area");
static int verb_authenticate_homes(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        char **args = strv_skip(argv, 1);
        if (args) {
                STRV_FOREACH(arg, args)
                        RET_GATHER(r, authenticate_home(bus, *arg));

                return r;
        } else {
                _cleanup_free_ char *myself = getusername_malloc();
                if (!myself)
                        return log_oom();

                return authenticate_home(bus, myself);
        }
}

VERB_GROUP("User Migration Commands");
VERB(verb_adopt_home, "adopt", "PATH…", VERB_ANY, VERB_ANY, 0,
     "Add an existing home area on this system");
static int verb_adopt_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r, ret = 0;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                r = bus_message_new_method_call(bus, &m, bus_mgr, "AdoptHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "st", *i, UINT64_C(0));
                if (r < 0)
                        return bus_log_create_error(r);

                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to adopt home: %s", bus_error_message(&error, r));
                        if (ret == 0)
                                ret = r;
                }
        }

        return ret;
}

static int register_home_common(sd_bus *bus, sd_json_variant *v) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *_bus = NULL;
        int r;

        assert(v);

        if (!bus) {
                r = acquire_bus(&_bus);
                if (r < 0)
                        return r;
                bus = _bus;
        }

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        r = bus_message_new_method_call(bus, &m, bus_mgr, "RegisterHome");
        if (r < 0)
                return bus_log_create_error(r);

        _cleanup_free_ char *formatted = NULL;
        r = sd_json_variant_format(v, /* flags= */ 0, &formatted);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON record: %m");

        r = sd_bus_message_append(m, "s", formatted);
        if (r < 0)
                return bus_log_create_error(r);

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to register home: %s", bus_error_message(&error, r));

        return 0;
}

static int register_home_one(sd_bus *bus, FILE *f, const char *path) {
        int r;

        assert(bus);
        assert(path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned line = 0, column = 0;
        r = sd_json_parse_file(f, path, SD_JSON_PARSE_MUST_BE_OBJECT|SD_JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return log_error_errno(r, "[%s:%u:%u] Failed to parse user record: %m", path, line, column);

        return register_home_common(bus, v);
}

VERB(verb_register_home, "register", "PATH…", VERB_ANY, VERB_ANY, 0,
     "Register a user record locally");
static int verb_register_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        if (arg_identity) {
                if (argc > 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not accepting an arguments if --identity= is specified, refusing.");

                return register_home_one(bus, /* f= */ NULL, arg_identity);
        }

        if (argc == 1 || (argc == 2 && streq(argv[1], "-")))
                return register_home_one(bus, /* f= */ stdin, "<stdio>");

        r = 0;
        STRV_FOREACH(i, strv_skip(argv, 1)) {
                if (streq(*i, "-"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Refusing reading from standard input if multiple user records are specified.");

                RET_GATHER(r, register_home_one(bus, /* f= */ NULL, *i));
        }

        return r;
}

VERB(verb_unregister_home, "unregister", "USER…", 2, VERB_ANY, 0,
     "Unregister a user record locally");
static int verb_unregister_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        int ret = 0;
        STRV_FOREACH(i, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
                r = bus_message_new_method_call(bus, &m, bus_mgr, "UnregisterHome");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "s", *i);
                if (r < 0)
                        return bus_log_create_error(r);

                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = sd_bus_call(bus, m, HOME_SLOW_BUS_CALL_TIMEOUT_USEC, &error, /* ret_reply= */ NULL);
                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to unregister home: %s", bus_error_message(&error, r)));
        }

        return ret;
}

VERB_GROUP("Signing Keys Commands");
VERB_NOARG(verb_list_signing_keys, "list-signing-keys",
           "List home signing keys");
static int verb_list_signing_keys(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        r = bus_call_method(bus, bus_mgr, "ListSigningKeys", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list signing keys: %s", bus_error_message(&error, r));

        _cleanup_(table_unrefp) Table *table = table_new("name", "key");
        if (!table)
                return log_oom();

        r = sd_bus_message_enter_container(reply, 'a', "(sst)");
        if (r < 0)
                return bus_log_parse_error(r);

        for (;;) {
                const char *name, *pem;

                r = sd_bus_message_read(reply, "(sst)", &name, &pem, NULL);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                _cleanup_free_ char *h = NULL;
                if (!sd_json_format_enabled(arg_json_format_flags)) {
                        /* Let's decode the PEM key to DER (so that we lose prefix/suffix), then truncate it
                         * for display reasons. */

                        r = dlopen_libcrypto(LOG_DEBUG);
                        if (r < 0)
                                return r;

                        _cleanup_(EVP_PKEY_freep) EVP_PKEY *key = NULL;
                        r = openssl_pubkey_from_pem(pem, SIZE_MAX, &key);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse PEM: %m");

                        _cleanup_free_ void *der = NULL;
                        int n = sym_i2d_PUBKEY(key, (unsigned char**) &der);
                        if (n < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to encode key as DER.");

                        ssize_t m = base64mem(der, MIN(n, 64), &h);
                        if (m < 0)
                                return log_oom();
                        if (n > 64) /* check if we truncated the original version */
                                if (!strextend(&h, glyph(GLYPH_ELLIPSIS)))
                                        return log_oom();
                }

                r = table_add_many(
                                table,
                                TABLE_STRING, name,
                                TABLE_STRING, h ?: pem);
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
                        printf("No signing keys.\n");
                else
                        printf("\n%zu signing keys listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

VERB(verb_get_signing_key, "get-signing-key", "[NAME…]", VERB_ANY, VERB_ANY, 0,
     "Get a named home signing key");
static int verb_get_signing_key(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        char **keys = argc >= 2 ? strv_skip(argv, 1) : STRV_MAKE("local.public");
        int ret = 0;
        STRV_FOREACH(k, keys) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                r = bus_call_method(bus, bus_mgr, "GetSigningKey", &error, &reply, "s", *k);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to get signing key '%s': %s", *k, bus_error_message(&error, r)));
                        continue;
                }

                const char *pem;
                r = sd_bus_message_read(reply, "st", &pem, NULL);
                if (r < 0) {
                        RET_GATHER(ret, bus_log_parse_error(r));
                        continue;
                }

                fputs(pem, stdout);
                if (!endswith(pem, "\n"))
                        fputc('\n', stdout);

                fflush(stdout);
        }

        return ret;
}

static int add_signing_key_one(sd_bus *bus, const char *fn, FILE *key) {
        int r;

        assert_se(bus);
        assert_se(fn);
        assert_se(key);

        _cleanup_free_ char *pem = NULL;
        r = read_full_stream(key, &pem, /* ret_size= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read key '%s': %m", fn);

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_call_method(bus, bus_mgr, "AddSigningKey", &error, /* ret_reply= */ NULL, "sst", fn, pem, UINT64_C(0));
        if (r < 0)
                return log_error_errno(r, "Failed to add signing key '%s': %s", fn, bus_error_message(&error, r));

        return 0;
}

VERB(verb_add_signing_key, "add-signing-key", "FILE…", VERB_ANY, VERB_ANY, 0,
     "Add home signing key");
static int verb_add_signing_key(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        int ret = EXIT_SUCCESS;
        if (argc < 2 || streq(argv[1], "-")) {
                if (!arg_key_name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key name must be specified via --key-name= when reading key from standard input, refusing.");

                RET_GATHER(ret, add_signing_key_one(bus, arg_key_name, stdin));
        } else {
                /* Refuse if more han one key is specified in combination with --key-name= */
                if (argc >= 3 && arg_key_name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--key-name= is not supported if multiple signing keys are specified, refusing.");

                STRV_FOREACH(k, strv_skip(argv, 1)) {

                        if (streq(*k, "-"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Refusing to read from standard input if multiple keys are specified.");

                        _cleanup_free_ char *fn = NULL;
                        if (!arg_key_name) {
                                r = path_extract_filename(*k, &fn);
                                if (r < 0) {
                                        RET_GATHER(ret, log_error_errno(r, "Failed to extract filename from path '%s': %m", *k));
                                        continue;
                                }
                        }

                        _cleanup_fclose_ FILE *f = fopen(*k, "re");
                        if (!f) {
                                RET_GATHER(ret, log_error_errno(errno, "Failed to open '%s': %m", *k));
                                continue;
                        }

                        RET_GATHER(ret, add_signing_key_one(bus, fn ?: arg_key_name, f));
                }
        }

        return ret;
}

static int add_signing_keys_from_credentials(void) {
        int r;

        _cleanup_close_ int fd = open_credentials_dir();
        if (IN_SET(fd, -ENXIO, -ENOENT)) /* Credential env var not set, or dir doesn't exist. */
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open credentials directory: %m");

        _cleanup_free_ DirectoryEntries *des = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &des);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate credentials: %m");

        int ret = 0;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                struct dirent *de = *i;
                if (de->d_type != DT_REG)
                        continue;

                const char *e = startswith(de->d_name, "home.add-signing-key.");
                if (!e)
                        continue;

                if (!filename_is_valid(e))
                        continue;

                if (!bus) {
                        r = acquire_bus(&bus);
                        if (r < 0)
                                return r;
                }

                _cleanup_fclose_ FILE *f = NULL;
                r = xfopenat(fd, de->d_name, "re", O_NOFOLLOW, &f);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to open credential '%s': %m", de->d_name));
                        continue;
                }

                RET_GATHER(ret, add_signing_key_one(bus, e, f));
        }

        return ret;
}

static int remove_signing_key_one(sd_bus *bus, const char *fn) {
        int r;

        assert_se(bus);
        assert_se(fn);

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_call_method(bus, bus_mgr, "RemoveSigningKey", &error, /* ret_reply= */ NULL, "st", fn, UINT64_C(0));
        if (r < 0)
                return log_error_errno(r, "Failed to remove signing key '%s': %s", fn, bus_error_message(&error, r));

        return 0;
}

VERB(verb_remove_signing_key, "remove-signing-key", "NAME…", 2, VERB_ANY, 0,
     "Remove home signing key");
static int verb_remove_signing_key(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = EXIT_SUCCESS;
        STRV_FOREACH(k, strv_skip(argv, 1))
                RET_GATHER(r, remove_signing_key_one(bus, *k));

        return r;
}

VERB_GROUP("Lock/Unlock Commands");
VERB(verb_lock_home, "lock", "USER…", 2, VERB_ANY, 0,
     "Temporarily lock an active home area");
static int verb_lock_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB(verb_unlock_home, "unlock", "USER…", 2, VERB_ANY, 0,
     "Unlock a temporarily locked home area");
static int verb_unlock_home(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB_NOARG(verb_lock_all_homes, "lock-all",
           "Lock all suitable home areas");
static int verb_lock_all_homes(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

VERB_GROUP("Other Commands");
VERB_NOARG(verb_rebalance, "rebalance",
           "Rebalance free space between home areas");
static int verb_rebalance(int argc, char *argv[], uintptr_t _data, void *userdata) {
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

static int create_or_register_from_credentials(void) {
        int r;

        _cleanup_close_ int fd = open_credentials_dir();
        if (IN_SET(fd, -ENXIO, -ENOENT)) /* Credential env var not set, or dir doesn't exist. */
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open credentials directory: %m");

        _cleanup_free_ DirectoryEntries *des = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &des);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate credentials: %m");

        int ret = 0, n_processed = 0;
        FOREACH_ARRAY(i, des->entries, des->n_entries) {
                struct dirent *de = *i;
                if (de->d_type != DT_REG)
                        continue;

                enum {
                        OPERATION_CREATE,
                        OPERATION_REGISTER,
                } op;
                const char *e;
                if ((e = startswith(de->d_name, "home.create.")))
                        op = OPERATION_CREATE;
                else if ((e = startswith(de->d_name, "home.register.")))
                        op = OPERATION_REGISTER;
                else
                        continue;

                if (!valid_user_group_name(e, /* flags= */ 0)) {
                        log_notice("Skipping over credential with name that is not a suitable user name: %s", de->d_name);
                        continue;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *identity = NULL;
                unsigned line = 0, column = 0;
                r = sd_json_parse_file_at(
                                /* f= */ NULL,
                                fd,
                                de->d_name,
                                /* flags= */ SD_JSON_PARSE_MUST_BE_OBJECT,
                                &identity,
                                &line,
                                &column);
                if (r < 0) {
                        log_warning_errno(r, "[%s:%u:%u] Failed to parse user record in credential, ignoring: %m", de->d_name, line, column);
                        continue;
                }

                sd_json_variant *un = sd_json_variant_by_key(identity, "userName");
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

                if (op == OPERATION_CREATE)
                        r = create_home_common(identity, /* show_enforce_password_policy_hint= */ false);
                else
                        r = register_home_common(/* bus= */ NULL, identity);
                if (r >= 0)
                        n_processed++;

                RET_GATHER(ret, r);
        }

        return ret < 0 ? ret : n_processed;
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

static int username_is_ok(const char *name, void *userdata) {
        int r;

        assert(name);

        if (!valid_user_group_name(name, /* flags= */ 0)) {
                log_notice("Specified user name is not a valid UNIX user name, try again: %s", name);
                return false;
        }

        r = userdb_by_name(name, /* match= */ NULL, USERDB_SUPPRESS_SHADOW, /* ret= */ NULL);
        if (r == -ESRCH)
                return true;
        if (r < 0)
                return log_error_errno(r, "Failed to check if specified user '%s' already exists: %m", name);

        log_notice("Specified user '%s' exists already, try again.", name);
        return false;
}

static int create_interactively(void) {
        _cleanup_free_ char *username = NULL;
        int r;

        if (!arg_prompt_new_user) {
                log_debug("Prompting for user creation was not requested.");
                return 0;
        }

        /* Needs to be called before mute_console or it will garble the screen */
        (void) plymouth_hide_splash();

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *mute_console_link = NULL;
        (void) mute_console(&mute_console_link);

        (void) terminal_reset_defensive_locked(STDOUT_FILENO, /* flags= */ 0);

        if (arg_chrome)
                chrome_show("Create a User Account", /* bottom= */ NULL);

        DEFER_VOID_CALL(chrome_hide);

        if (emoji_enabled()) {
                fputs(glyph(GLYPH_HOME), stdout);
                putchar(' ');
        }
        printf("Please create your user account!\n\n");

        r = prompt_loop("Please enter user name to create",
                        GLYPH_IDCARD,
                        /* menu= */ NULL,
                        /* accepted= */ NULL,
                        /* ellipsize_percentage= */ 60,
                        /* n_columns= */ 3,
                        /* column_width= */ 20,
                        username_is_ok,
                        /* refresh= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_MAY_SKIP|PROMPT_SILENT_VALIDATE,
                        &username);
        if (r < 0)
                return r;
        if (isempty(username))
                return 0;

        r = sd_json_variant_set_field_string(&arg_identity_extra, "userName", username);
        if (r < 0)
                return log_error_errno(r, "Failed to set userName field: %m");

        /* Let's not insist on a strong password in the firstboot interactive interface. Insisting on this is
         * really annoying, as the user cannot just invoke the tool again with "--enforce-password-policy=no"
         * because after all the tool is called from the boot process, and not from an interactive
         * shell. Moreover, when setting up an initial system we can assume the user owns it, and hence we
         * don't need to hard enforce some policy on password strength some organization or OS vendor
         * requires. Note that this just disables the *strict* enforcement of the password policy. Even with
         * this disabled we'll still tell the user in the UI that the password is too weak and suggest better
         * ones, even if we then accept the weak ones if the user insists, by repeating it. */
        r = sd_json_variant_set_field_boolean(&arg_identity_extra, "enforcePasswordPolicy", false);
        if (r < 0)
                return log_error_errno(r, "Failed to set enforcePasswordPolicy field: %m");

        if (arg_prompt_groups) {
                _cleanup_strv_free_ char **groups = NULL;

                putchar('\n');

                r = prompt_groups(username, &groups);
                if (r < 0)
                        return r;

                if (!strv_isempty(groups)) {
                        r = sd_json_variant_set_field_strv(&arg_identity_extra, "memberOf", groups);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set memberOf field: %m");
                }
        }

        if (arg_prompt_shell) {
                _cleanup_free_ char *shell = NULL;

                putchar('\n');

                r = prompt_shell(username, &shell);
                if (r < 0)
                        return r;

                if (!isempty(shell)) {
                        log_info("Selected %s as the shell for user %s", shell, username);

                        r = sd_json_variant_set_field_string(&arg_identity_extra, "shell", shell);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set shell field: %m");
                }
        }

        putchar('\n');

        r = create_home_common(/* input= */ NULL, /* show_enforce_password_policy_hint= */ false);
        if (r < 0)
                return r;

        log_info("Successfully created account '%s'.", username);
        return 0;
}

VERB_NOARG(verb_firstboot, "firstboot",
           "Run first-boot home area creation wizard");
static int verb_firstboot(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        /* Let's honour the systemd.firstboot kernel command line option, just like the systemd-firstboot
         * tool. */

        bool enabled;
        r = proc_cmdline_get_bool("systemd.firstboot", /* flags= */ 0, &enabled);
        if (r < 0)
                return log_error_errno(r, "Failed to parse systemd.firstboot= kernel command line argument, ignoring: %m");
        if (r > 0 && !enabled) {
                log_debug("Found systemd.firstboot=no kernel command line argument, turning off all prompts.");
                arg_prompt_new_user = false;
        }

        int ret = 0;

        RET_GATHER(ret, add_signing_keys_from_credentials());

        r = create_or_register_from_credentials();
        RET_GATHER(ret, r);
        bool existing_users = r > 0;

        r = getenv_bool("SYSTEMD_HOME_FIRSTBOOT_OVERRIDE");
        if (r == 0)
                return 0;
        if (r < 0) {
                if (r != -ENXIO)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_HOME_FIRSTBOOT_OVERRIDE, ignoring: %m");

                if (!existing_users) {
                        r = has_regular_user();
                        if (r < 0)
                                return r;

                        existing_users = r > 0;
                }
                if (existing_users) {
                        log_info("Regular user already present in user database, skipping interactive user creation.");
                        return 0;
                }
        }

        RET_GATHER(ret, create_interactively());
        return ret;
}

#define drop_from_identity(...) _drop_from_identity(STRV_MAKE(__VA_ARGS__))

static int _drop_from_identity(char **fields) {
        int r;

        /* If we are called to update an identity record and drop some field, let's keep track of what to
         * remove from the old record */
        r = strv_extend_strv(&arg_identity_filter, fields, /* filter_duplicates= */ true);
        if (r < 0)
                return log_oom();

        /* Let's also drop the field if it was previously set to a new value on the same command line */
        r = sd_json_variant_filter(&arg_identity_extra, fields);
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        r = sd_json_variant_filter(&arg_identity_extra_this_machine, fields);
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        r = sd_json_variant_filter(&arg_identity_extra_privileged, fields);
        if (r < 0)
                return log_error_errno(r, "Failed to filter JSON identity data: %m");

        return 0;
}

static int parse_ssh_authorized_keys(sd_json_variant **identity, const char *field, const char *arg) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_strv_free_ char **l = NULL, **add = NULL;
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        if (arg[0] == '@') {
                /* If prefixed with '@', read from a file */

                _cleanup_fclose_ FILE *f = fopen(arg + 1, "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open '%s': %m", arg + 1);

                for (;;) {
                        _cleanup_free_ char *line = NULL;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read from '%s': %m", arg + 1);
                        if (r == 0)
                                break;

                        if (isempty(line) || line[0] == '#')
                                continue;

                        r = strv_consume(&add, TAKE_PTR(line));
                        if (r < 0)
                                return log_oom();
                }
        } else {
                /* Otherwise, assume it's a literal key. Let's do some superficial checks
                 * before accepting it though. */

                if (string_has_cc(arg, NULL))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Authorized key contains control characters, refusing.");
                if (arg[0] == '#')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified key is a comment?");

                add = strv_new(arg);
                if (!add)
                        return log_oom();
        }

        v = sd_json_variant_ref(sd_json_variant_by_key(*identity, field));
        if (v) {
                r = sd_json_variant_strv(v, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s list: %m", field);
        }

        r = strv_extend_strv_consume(&l, TAKE_PTR(add), /* filter_duplicates= */ true);
        if (r < 0)
                return log_oom();

        v = sd_json_variant_unref(v);

        r = sd_json_variant_new_array_strv(&v, l);
        if (r < 0)
                return log_oom();

        r = sd_json_variant_set_field(identity, field, v);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);

        return 0;
}

static int parse_string_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        r = sd_json_variant_set_field_string(identity, field, arg);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_home_directory_field(sd_json_variant **identity, const char *field, const char *arg) {
        _cleanup_free_ char *hd = NULL;
        int r;

        assert(identity);
        assert(field);

        if (!isempty(arg)) {
                r = parse_path_argument(arg, /* suppress_root= */ false, &hd);
                if (r < 0)
                        return r;

                if (!valid_home(hd))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Home directory '%s' not valid.", hd);
        }

        return parse_string_field(identity, field, hd);
}

static int parse_realm_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (!isempty(arg)) {
                r = dns_name_is_valid(arg);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether realm '%s' is a valid DNS domain: %m", arg);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Realm '%s' is not a valid DNS domain.", arg);
        }

        return parse_string_field(identity, field, arg);
}

static int parse_path_field(sd_json_variant **identity, const char *field, const char *arg) {
        _cleanup_free_ char *v = NULL;
        int r;

        assert(identity);
        assert(field);

        if (!isempty(arg)) {
                r = parse_path_argument(arg, /* suppress_root= */ false, &v);
                if (r < 0)
                        return r;
        }

        return parse_string_field(identity, field, v);
}

static int parse_filename_field(sd_json_variant **identity, const char *field, const char *arg) {
        assert(identity);
        assert(field);

        if (!isempty(arg) && !filename_is_valid(arg))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Parameter for %s field not a valid filename: %s", field, arg);

        return parse_string_field(identity, field, arg);
}

static int parse_unsigned_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        unsigned n;
        r = safe_atou(arg, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);

        r = sd_json_variant_set_field_unsigned(identity, field, n);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_u64_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        uint64_t n;
        r = safe_atou64(arg, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);

        r = sd_json_variant_set_field_unsigned(identity, field, n);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_size_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        uint64_t n;
        r = parse_size(arg, 1024, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);

        r = sd_json_variant_set_field_unsigned(identity, field, n);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_boolean_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        r = parse_boolean(arg);
        if (r < 0)
                return log_error_errno(r, "Failed to parse boolean parameter %s: %s", field, arg);

        r = sd_json_variant_set_field_boolean(identity, field, r > 0);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_mode_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        mode_t mode;
        r = parse_mode(arg, &mode);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Access mode '%s' not valid.", arg);

        r = sd_json_variant_set_field_unsigned(identity, field, mode);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_timestamp_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        usec_t n;
        r = parse_timestamp(arg, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);

        r = sd_json_variant_set_field_unsigned(identity, field, n);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_time_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        usec_t n;
        r = parse_sec(arg, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);

        r = sd_json_variant_set_field_unsigned(identity, field, n);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_uid_field(sd_json_variant **identity, const char *field, const char *arg) {
        uid_t uid;
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        r = parse_uid(arg, &uid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse UID '%s'.", arg);

        const char *bad_range =
                uid_is_system(uid) ? "in system range" :
                uid_is_greeter(uid) ? "in greeter range" :
                uid_is_dynamic(uid) ? "in dynamic ragne" :
                uid == UID_NOBODY ? "nobody UID" : NULL;
        if (bad_range)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID "UID_FMT" is %s, refusing.", uid, bad_range);

        r = sd_json_variant_set_field_unsigned(identity, field, uid);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_nice_field(sd_json_variant **identity, const char *field, const char *arg) {
        int nc, r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        r = parse_nice(arg, &nc);
        if (r < 0)
                return log_error_errno(r, "Failed to parse nice level '%s': %m", arg);

        r = sd_json_variant_set_field_integer(identity, field, nc);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_auto_resize_mode_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (!isempty(arg)) {
                r = auto_resize_mode_from_string(arg);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);
                arg = auto_resize_mode_to_string(r);
        }

        return parse_string_field(identity, field, arg);
}

static int parse_rebalance_weight(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        uint64_t u;
        if (streq(arg, "off"))
                u = REBALANCE_WEIGHT_OFF;
        else {
                r = safe_atou64(arg, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse rebalance weight parameter: %s", arg);

                if (u < REBALANCE_WEIGHT_MIN || u > REBALANCE_WEIGHT_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                               "Rebalancing weight out of valid range %" PRIu64 "%s%" PRIu64 ": %s",
                                               REBALANCE_WEIGHT_MIN, glyph(GLYPH_ELLIPSIS), REBALANCE_WEIGHT_MAX,
                                               arg);
        }

        /* Drop from per machine stuff and everywhere */
        r = drop_from_identity(field);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field_unsigned(identity, field, u);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_rlimit_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg)) {
                /* Remove all resource limits */

                r = drop_from_identity(field);
                if (r < 0)
                        return r;

                arg_identity_filter_rlimits = strv_free(arg_identity_filter_rlimits);
                *identity = sd_json_variant_unref(*identity);
                return 0;
        }

        const char *eq = strchr(arg, '=');
        if (!eq)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't parse resource limit assignment: %s", arg);

        _cleanup_free_ char *s = strndup(arg, eq - arg);
        if (!s)
                return log_oom();

        int limit = rlimit_from_string_harder(s);
        if (limit < 0)
                return log_error_errno(limit, "Unknown resource limit type: %s", s);

        const char *rlimit_field = strjoina("RLIMIT_", rlimit_to_string(limit));

        if (isempty(eq + 1)) {
                /* Remove only the specific rlimit */

                r = strv_extend(&arg_identity_filter_rlimits, rlimit_field);
                if (r < 0)
                        return r;

                r = sd_json_variant_filter(identity, STRV_MAKE(rlimit_field));
                if (r < 0)
                        return log_error_errno(r, "Failed to filter JSON identity data: %m");
                return 0;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jcur = NULL, *jmax = NULL;
        struct rlimit rl;

        r = rlimit_parse(limit, eq + 1, &rl);
        if (r < 0)
                return log_error_errno(r, "Failed to parse resource limit value: %s", eq + 1);

        r = rl.rlim_cur == RLIM_INFINITY ? sd_json_variant_new_null(&jcur) : sd_json_variant_new_unsigned(&jcur, rl.rlim_cur);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate json variant: %m");

        r = rl.rlim_max == RLIM_INFINITY ? sd_json_variant_new_null(&jmax) : sd_json_variant_new_unsigned(&jmax, rl.rlim_max);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate json variant: %m");

        r = sd_json_variant_set_fieldbo(identity, rlimit_field,
                                        SD_JSON_BUILD_PAIR_VARIANT("cur", jcur),
                                        SD_JSON_BUILD_PAIR_VARIANT("max", jmax));
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", rlimit_field);
        return 0;
}

static int parse_disk_size_field(sd_json_variant **identity, const char *arg) {
        int r;

        assert(identity);

        if (isempty(arg)) {
                r = drop_from_identity("diskSize", "diskSizeRelative", "rebalanceWeight");
                if (r < 0)
                        return r;

                arg_disk_size = arg_disk_size_relative = UINT64_MAX;
                return 0;
        }

        r = parse_permyriad(arg);
        if (r < 0) {
                r = parse_disk_size(arg, &arg_disk_size);
                if (r < 0)
                        return r;

                r = drop_from_identity("diskSizeRelative");
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field_unsigned(identity, "diskSize", arg_disk_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to set %s field: %m", "diskSize");

                arg_disk_size_relative = UINT64_MAX;
        } else {
                /* Normalize to UINT32_MAX == 100% */
                arg_disk_size_relative = UINT32_SCALE_FROM_PERMYRIAD(r);

                r = drop_from_identity("diskSize");
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field_unsigned(identity, "diskSizeRelative", arg_disk_size_relative);
                if (r < 0)
                        return log_error_errno(r, "Failed to set %s field: %m", "diskSizeRelative");

                arg_disk_size = UINT64_MAX;
        }

        /* Automatically turn off the rebalance logic if user configured a size explicitly */
        r = sd_json_variant_set_field_unsigned(identity, "rebalanceWeight", REBALANCE_WEIGHT_OFF);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", "rebalanceWeight");
        return 0;
}

static int parse_sector_size_field(sd_json_variant **identity, const char *field, const char *arg) {
        uint64_t ss;
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        r = parse_sector_size(arg, &ss);
        if (r < 0)
                return r;

        r = sd_json_variant_set_field_unsigned(identity, field, ss);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_weight_field(sd_json_variant **identity, const char *field, const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        uint64_t u;
        r = safe_atou64(arg, &u);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s parameter: %s", field, arg);

        if (!CGROUP_WEIGHT_IS_OK(u))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Weight %" PRIu64 " is out of valid range for field %s.", u, field);

        r = sd_json_variant_set_field_unsigned(identity, field, u);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_environment_field(sd_json_variant **identity, const char *field, const char *arg) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ne = NULL;
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        sd_json_variant *e = sd_json_variant_by_key(*identity, field);
        if (e) {
                r = sd_json_variant_strv(e, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON environment field: %m");
        }

        r = strv_env_replace_strdup_passthrough(&l, arg);
        if (r < 0)
                return log_error_errno(r, "Cannot assign environment variable %s: %m", arg);

        strv_sort(l);

        r = sd_json_variant_new_array_strv(&ne, l);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate json list: %m");

        r = sd_json_variant_set_field(identity, field, ne);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_language_field(char ***languages, const char *arg) {
        int r;

        assert(languages);

        if (isempty(arg)) {
                r = drop_from_identity("preferredLanguage", "additionalLanguages");
                if (r < 0)
                        return r;

                strv_freep(languages);
                return 0;
        }

        for (const char *p = arg;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",:", /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse locale list: %m");
                if (r == 0)
                        return 0;

                if (!locale_is_valid(word))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale '%s' is not valid.", word);

                if (locale_is_installed(word) <= 0)
                        log_warning("Locale '%s' is not installed, accepting anyway.", word);

                r = strv_consume(languages, TAKE_PTR(word));
                if (r < 0)
                        return log_oom();

                strv_uniq(*languages);
        }
}

static int parse_group_field(
                sd_json_variant **identity,
                const char *field,
                const char *arg) {
        int r;

        assert(identity);
        assert(field);

        if (isempty(arg))
                return drop_from_identity(field);

        for (const char *p = arg;;) {
                _cleanup_free_ char *word = NULL;
                _cleanup_strv_free_ char **list = NULL;

                r = extract_first_word(&p, &word, ",", /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse group list: %m");
                if (r == 0)
                        return 0;

                if (!valid_user_group_name(word, /* flags= */ 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid group name %s.", word);

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mo =
                        sd_json_variant_ref(sd_json_variant_by_key(*identity, field));

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
                        return log_error_errno(r, "Failed to allocate json list: %m");

                r = sd_json_variant_set_field(identity, field, mo);
                if (r < 0)
                        return log_error_errno(r, "Failed to set %s field: %m", field);
        }
}

static int parse_capability_set_field(
                sd_json_variant **identity,
                uint64_t *capability_set,
                const char *field,
                const char *arg) {

        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(identity);
        assert(capability_set);
        assert(field);
        assert(arg);

        r = parse_capability_set(arg, CAP_MASK_UNSET, capability_set);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid capabilities in capability string '%s'.", arg);
        if (r < 0)
                return log_error_errno(r, "Failed to parse capability string '%s': %m", arg);

        if (*capability_set == CAP_MASK_UNSET)
                return drop_from_identity(field);

        if (capability_set_to_strv(*capability_set, &l) < 0)
                return log_oom();

        r = sd_json_variant_set_field_strv(identity, field, l);
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field);
        return 0;
}

static int parse_tmpfs_limit_field(
                sd_json_variant **identity,
                const char *field,
                const char *field_scale,
                const char *arg) {
        int r;

        assert(identity);
        assert(field);
        assert(field_scale);

        if (isempty(arg))
                return drop_from_identity(field, field_scale);

        r = parse_permyriad(arg);
        if (r < 0) {
                uint64_t u;

                r = parse_size(arg, 1024, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse %s/%s parameter: %s", field, field_scale, arg);

                r = sd_json_variant_set_field_unsigned(identity, field, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to set %s field: %m", field);

                return drop_from_identity(field_scale);
        }

        r = sd_json_variant_set_field_unsigned(identity, field_scale, UINT32_SCALE_FROM_PERMYRIAD(r));
        if (r < 0)
                return log_error_errno(r, "Failed to set %s field: %m", field_scale);

        return drop_from_identity(field);
}

static int parse_pkcs11_token_uri_field(const char *arg) {
        int r;

        assert(arg);

        if (streq(arg, "list"))
                return pkcs11_list_tokens();

        /* If --pkcs11-token-uri= is specified we always drop everything old */
        r = drop_from_identity("pkcs11TokenUri", "pkcs11EncryptedKey");
        if (r < 0)
                return r;

        if (isempty(arg)) {
                arg_pkcs11_token_uri = strv_free(arg_pkcs11_token_uri);
                return 1;
        }

        if (streq(arg, "auto")) {
                char *found;
                r = pkcs11_find_token_auto(&found);
                if (r < 0)
                        return r;

                r = strv_consume(&arg_pkcs11_token_uri, found);
        } else {
                if (!pkcs11_uri_valid(arg))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid PKCS#11 URI: %s", arg);

                r = strv_extend(&arg_pkcs11_token_uri, arg);
        }
        if (r < 0)
                return r;

        strv_uniq(arg_pkcs11_token_uri);
        return 1;
}

static int parse_fido2_device_field(const char *arg) {
        int r;

        assert(arg);

        if (streq(arg, "list"))
                return fido2_list_devices();

        r = drop_from_identity("fido2HmacCredential", "fido2HmacSalt");
        if (r < 0)
                return r;

        if (isempty(arg)) {
                arg_fido2_device = strv_free(arg_fido2_device);
                return 1;
        }

        if (streq(arg, "auto")) {
                char *found;
                r = fido2_find_device_auto(&found);
                if (r < 0)
                        return r;

                r = strv_consume(&arg_fido2_device, found);
        } else
                r = strv_extend(&arg_fido2_device, arg);
        if (r < 0)
                return r;

        strv_uniq(arg_fido2_device);
        return 1;
}

static int help(void) {
        static const char* const vgroups[] = {
                "Basic User Manipulation Commands",
                "Advanced User Manipulation Commands",
                "User Migration Commands",
                "Signing Keys Commands",
                "Lock/Unlock Commands",
                "Other Commands",
        };

        static const char* const ogroups[] = {
                NULL,
                "General User Record Properties",
                "Authentication User Record Properties",
                "Blob Directory User Record Properties",
                "Account Management User Record Properties",
                "Password Policy User Record Properties",
                "Resource Management User Record Properties",
                "Storage User Record Properties",
                "LUKS Storage User Record Properties",
                "Mounting User Record Properties",
                "CIFS User Record Properties",
                "Login Behaviour User Record Properties",
        };

        Table *vtables[ELEMENTSOF(vgroups)] = {};
        CLEANUP_ELEMENTS(vtables, table_unref_array_clear);
        Table *otables[ELEMENTSOF(ogroups)] = {};
        CLEANUP_ELEMENTS(otables, table_unref_array_clear);
        int r;

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                r = verbs_get_help_table_group(vgroups[i], &vtables[i]);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < ELEMENTSOF(ogroups); i++) {
                r = option_parser_get_help_table_group(ogroups[i], &otables[i]);
                if (r < 0)
                        return r;
        }

        /* The two groups are not synchronized because the option table is very wide. */

        assert_cc(ELEMENTSOF(vtables) == 6);
        (void) table_sync_column_widths(0, vtables[0], vtables[1], vtables[2],
                                        vtables[3], vtables[4], vtables[5]);

        assert_cc(ELEMENTSOF(otables) == 12);
        (void) table_sync_column_widths(0, otables[0], otables[1], otables[2], otables[3],
                                        otables[4], otables[5], otables[6], otables[7],
                                        otables[8], otables[9], otables[10], otables[11]);

        pager_open(arg_pager_flags);

        help_cmdline("[OPTIONS…] COMMAND …");
        help_abstract("Create, manipulate or inspect home directories.");

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                help_section(vgroups[i]);
                r = table_print_or_warn(vtables[i]);
                if (r < 0)
                        return r;
        }

        help_section("Options");
        r = table_print_or_warn(otables[0]);
        if (r < 0)
                return r;

        for (size_t i = 1; i < ELEMENTSOF(ogroups); i++) {
                help_section(ogroups[i]);
                r = table_print_or_warn(otables[i]);
                if (r < 0)
                        return r;
        }

        help_man_page_reference("homectl", "1");

        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        _cleanup_strv_free_ char **arg_languages = NULL;
        int r;

        /* This points to one of arg_identity_extra, arg_identity_extra_this_machine,
         * arg_identity_extra_other_machines, in order to redirect changes on the next property being set to
         * this part of the identity, instead of the default. */
        sd_json_variant **match_identity = NULL;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        /* Eventually we should probably turn this into a proper --dry-run option, but as long as it is not
         * hooked up everywhere let's make it an environment variable only. */
        r = getenv_bool("SYSTEMD_HOME_DRY_RUN");
        if (r >= 0)
                arg_dry_run = r;
        else if (r != -ENXIO)
                log_debug_errno(r, "Unable to parse $SYSTEMD_HOME_DRY_RUN, ignoring: %m");

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("offline", NULL, "Don't update record embedded in home directory"):
                        arg_offline = true;
                        break;

                OPTION_COMMON_HOST:
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = opts.arg;
                        break;

                OPTION_COMMON_MACHINE:
                        r = parse_machine_argument(opts.arg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                OPTION('I', "identity", "PATH", "Read JSON identity from file"):
                        arg_identity = opts.arg;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION_LONG("export-format", "FORMAT",
                            "Strip JSON inspection data (full, stripped, minimal)"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(export_format, ExportFormat, _EXPORT_FORMAT_MAX);

                        arg_export_format = export_format_from_string(opts.arg);
                        if (arg_export_format < 0)
                                return log_error_errno(arg_export_format, "Invalid export format: %s", opts.arg);

                        break;

                OPTION_SHORT('E', NULL, "Same as -j --export-format=stripped"): {}
                OPTION_HELP_VERBATIM("-EE", "Same as -j --export-format=minimal"):
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

                OPTION_LONG("key-name", "NAME", "Key name when adding a signing key"):
                        if (!isempty(opts.arg) && !filename_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for --key-name= not a valid filename: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_key_name, empty_to_null(opts.arg));
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("seize", "BOOL",
                            "Whether to strip existing signatures of user record when creating"):
                        r = parse_boolean_argument("--seize=", opts.arg, &arg_seize);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("prompt-new-user", NULL,
                            "firstboot: Query user interactively for user to create"):
                        arg_prompt_new_user = true;
                        break;

                OPTION_LONG("prompt-groups", "BOOL",
                            "In first-boot mode, don't prompt for auxiliary group memberships"):
                        r = parse_boolean_argument("--prompt-groups=", opts.arg, &arg_prompt_groups);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("prompt-shell", "BOOL",
                            "In first-boot mode, don't prompt for shells"):
                        r = parse_boolean_argument("--prompt-shell=", opts.arg, &arg_prompt_shell);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("chrome", "BOOL",
                            "In first-boot mode, don't show colour bar at top and bottom of terminal"):
                        r = parse_boolean_argument("--chrome=", opts.arg, &arg_chrome);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("mute-console", "BOOL",
                            "In first-boot mode, tell kernel/PID 1 to not write to the console while running"):
                        r = parse_boolean_argument("--mute-console=", opts.arg, &arg_mute_console);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_GROUP("General User Record Properties"): {}

                OPTION('c', "real-name", "REALNAME", "Real name for user"): {}
                OPTION_LONG("comment", "REALNAME", /* help= */ NULL): /* Compat alias to keep things in sync with useradd(8) */
                        if (!isempty(opts.arg) && !valid_gecos(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid GECOS field '%s'.", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "realName", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("realm", "REALM", "Realm to create user in"):
                        r = parse_realm_field(&arg_identity_extra, "realm", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("alias", "ALIAS", "Define alias usernames for this account"):
                        r = parse_group_field(&arg_identity_extra, "aliases", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("email-address", "EMAIL", "Email address for user"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "emailAddress", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("location", "LOCATION", "Set location of user on earth"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "location", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "birth-date", "DATE",
                                  "Set user birth date (YYYY-MM-DD)"):
                        if (isempty(opts.arg)) {
                                r = drop_from_identity("birthDate");
                                if (r < 0)
                                        return r;
                        } else {
                                r = parse_birth_date(opts.arg, /* ret= */ NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Invalid birth date (expected YYYY-MM-DD): %s", opts.arg);

                                r = parse_string_field(&arg_identity_extra, "birthDate", opts.arg);
                                if (r < 0)
                                        return r;
                        }
                        break;

                OPTION_LONG("icon-name", "NAME", "Icon name for user"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "iconName", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('d', "home-dir", "PATH", "Home directory"): /* Compatible with useradd(8) */
                        r = parse_home_directory_field(&arg_identity_extra, "homeDirectory", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('u', "uid", "UID", "Numeric UID for user"): /* Compatible with useradd(8) */
                        r = parse_uid_field(&arg_identity_extra, "uid", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('G', "member-of", "GROUP", "Add user to group"): {}
                OPTION_LONG("groups", "GROUP", /* help= */ NULL): /* Compat alias to keep things in sync with useradd(8) */
                        r = parse_group_field(match_identity ?: &arg_identity_extra, "memberOf", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("capability-bounding-set", "CAPS", "Bounding POSIX capability set"):
                        r = parse_capability_set_field(match_identity ?: &arg_identity_extra,
                                                       &arg_capability_bounding_set,
                                                       "capabilityBoundingSet", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("capability-ambient-set", "CAPS", "Ambient POSIX capability set"):
                        r = parse_capability_set_field(match_identity ?: &arg_identity_extra,
                                                       &arg_capability_ambient_set,
                                                       "capabilityAmbientSet", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("access-mode", "MODE", "User home directory access mode"):
                        r = parse_mode_field(&arg_identity_extra, "accessMode", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("umask", "MODE", "Umask for user when logging in"):
                        r = parse_mode_field(match_identity ?: &arg_identity_extra, "umask", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('k', "skel", "PATH", "Skeleton directory to use"): /* Compatible with useradd(8) */
                        r = parse_path_field(match_identity ?: &arg_identity_extra_this_machine, "skeletonDirectory", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('s', "shell", "PATH", "Shell for account"): /* Compatible with useradd(8) */
                        if (!isempty(opts.arg) && !valid_shell(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Shell '%s' not valid.", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "shell", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("setenv", "VARIABLE[=VALUE]", "Set an environment variable at log-in"):
                        r = parse_environment_field(match_identity ?: &arg_identity_extra, "environment", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("timezone", "TIMEZONE", "Set a time-zone"):
                        if (!isempty(opts.arg) && !timezone_is_valid(opts.arg, LOG_DEBUG))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Timezone '%s' is not valid.", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "timeZone", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("language", "LOCALE", "Set preferred languages"):
                        r = parse_language_field(&arg_languages, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("default-area", "AREA", "Select default area"):
                        r = parse_filename_field(match_identity ?: &arg_identity_extra, "defaultArea", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Authentication User Record Properties"): {}

                OPTION_LONG("ssh-authorized-keys", "KEYS", "Specify SSH public keys"):
                        r = parse_ssh_authorized_keys(&arg_identity_extra_privileged, "sshAuthorizedKeys", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("pkcs11-token-uri", "URI",
                            "URI to PKCS#11 security token containing private key and matching X.509 certificate"):
                        r = parse_pkcs11_token_uri_field(opts.arg);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("fido2-device", "PATH",
                            "Path to FIDO2 hidraw device with hmac-secret extension"):
                        r = parse_fido2_device_field(opts.arg);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("fido2-with-client-pin", "BOOL",
                            "Whether to require entering a PIN to unlock the account"):
                        r = parse_boolean_argument("--fido2-with-client-pin=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_PIN, r);
                        break;

                OPTION_LONG("fido2-with-user-presence", "BOOL",
                            "Whether to require user presence to unlock the account"):
                        r = parse_boolean_argument("--fido2-with-user-presence=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UP, r);
                        break;

                OPTION_LONG("fido2-with-user-verification", "BOOL",
                            "Whether to require user verification to unlock the account"):
                        r = parse_boolean_argument("--fido2-with-user-verification=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_fido2_lock_with, FIDO2ENROLL_UV, r);
                        break;

                OPTION_LONG("recovery-key", "BOOL", "Add a recovery key"):
                        r = parse_boolean(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --recovery-key= argument: %s", opts.arg);
                        arg_recovery_key = r;

                        r = drop_from_identity("recoveryKey", "recoveryKeyType");
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Blob Directory User Record Properties"): {}

                OPTION('b', "blob", "[FILENAME=]PATH",
                       "Path to a replacement blob directory, or replace an individual files in the blob directory"): {}
                OPTION_LONG("avatar", "PATH", "Path to user avatar picture"): {}
                OPTION_LONG("login-background", "PATH", "Path to user login background picture"): {
                        _cleanup_close_ int fd = -EBADF;
                        _cleanup_free_ char *path = NULL, *filename = NULL;
                        const char *long_code = opts.opt->long_code;

                        if (streq(long_code, "blob")) {
                                const char *eq;

                                if (isempty(opts.arg)) { /* --blob= deletes everything, including existing blob dirs */
                                        hashmap_clear(arg_blob_files);
                                        arg_blob_dir = mfree(arg_blob_dir);
                                        arg_blob_clear = true;
                                        break;
                                }

                                eq = strrchr(opts.arg, '=');
                                if (!eq) { /* --blob=/some/path replaces the blob dir */
                                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_blob_dir);
                                        if (r < 0)
                                                return r;
                                        break;
                                }

                                /* --blob=filename=/some/path replaces the file "filename" with /some/path */
                                filename = strndup(opts.arg, eq - opts.arg);
                                if (!filename)
                                        return log_oom();

                                if (isempty(filename))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't parse blob file assignment: %s", opts.arg);
                                if (!suitable_blob_filename(filename))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid blob filename: %s", filename);

                                r = parse_path_argument(eq + 1, /* suppress_root= */ false, &path);
                                if (r < 0)
                                        return r;
                        } else {
                                filename = strdup(long_code);
                                if (!filename)
                                        return log_oom();

                                r = parse_path_argument(opts.arg, /* suppress_root= */ false, &path);
                                if (r < 0)
                                        return r;
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

                OPTION_GROUP("Account Management User Record Properties"): {}

                OPTION_LONG("locked", "BOOL", "Set locked account state"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "locked", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("not-before", "TIMESTAMP", "Do not allow logins before"): {}
                OPTION_LONG("not-after", "TIMESTAMP", "Do not allow logins after"): {}
                OPTION_LONG("expiredate", "TIMESTAMP", /* help= */ NULL): /* Compat alias for -e to keep things in sync with useradd(8) */ {
                        const char *field = streq(opts.opt->long_code, "not-before") ? "notBeforeUSec" : "notAfterUSec";

                        r = parse_timestamp_field(match_identity ?: &arg_identity_extra, field, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

                OPTION_SHORT('e', "TIMESTAMP", /* help= */ NULL): /* -e alias for --expiredate */
                        r = parse_timestamp_field(match_identity ?: &arg_identity_extra, "notAfterUSec", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("rate-limit-interval", "SECS", "Login rate-limit interval in seconds"):
                        r = parse_time_field(match_identity ?: &arg_identity_extra, "rateLimitIntervalUSec", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("rate-limit-burst", "NUMBER", "Login rate-limit attempts per interval"):
                        r = parse_unsigned_field(match_identity ?: &arg_identity_extra, "rateLimitBurst", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Password Policy User Record Properties"): {}

                OPTION_LONG("password-hint", "HINT", "Set Password hint"):
                        r = parse_string_field(&arg_identity_extra_privileged, "passwordHint", opts.arg);
                        if (r < 0)
                                return r;

                        string_erase((char *) opts.arg);
                        break;

                OPTION_LONG("enforce-password-policy", "BOOL",
                            "Control whether to enforce system's password policy for this user"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "enforcePasswordPolicy", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_SHORT('P', NULL, "Same as --enforce-password-policy=no"):
                        r = sd_json_variant_set_field_boolean(&arg_identity_extra, "enforcePasswordPolicy", false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set %s field: %m", "enforcePasswordPolicy");
                        break;

                OPTION_LONG("password-change-now", "BOOL",
                            "Require the password to be changed on next login"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "passwordChangeNow", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("password-change-min", "TIME", "Require minimum time between password changes"): {}
                OPTION_LONG("password-change-max", "TIME", "Require maximum time between password changes"): {}
                OPTION_LONG("password-change-warn", "TIME", "How much time to warn before password expiry"): {}
                OPTION_LONG("password-change-inactive", "TIME", "How much time to block password after expiry"): {
                        const char *lc = opts.opt->long_code;
                        const char *field =
                                streq(lc, "password-change-min")      ? "passwordChangeMinUSec" :
                                streq(lc, "password-change-max")      ? "passwordChangeMaxUSec" :
                                streq(lc, "password-change-warn")     ? "passwordChangeWarnUSec" :
                                streq(lc, "password-change-inactive") ? "passwordChangeInactiveUSec" :
                                                                        NULL;
                        assert(field);

                        r = parse_time_field(match_identity ?: &arg_identity_extra, field, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

                OPTION_GROUP("Resource Management User Record Properties"): {}

                OPTION_LONG("disk-size", "BYTES", "Size to assign the user on disk"):
                        r = parse_disk_size_field(match_identity ?: &arg_identity_extra_this_machine, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("nice", "NICE", "Nice level for user"):
                        r = parse_nice_field(match_identity ?: &arg_identity_extra, "niceLevel", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("rlimit", "LIMIT=VALUE[:VALUE]", "Set resource limits"):
                        r = parse_rlimit_field(&arg_identity_extra_rlimits, "resourceLimits", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tasks-max", "MAX", "Set maximum number of per-user tasks"):
                        r = parse_u64_field(match_identity ?: &arg_identity_extra, "tasksMax", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("memory-high", "BYTES", "Set high memory threshold in bytes"):
                        r = parse_size_field(match_identity ?: &arg_identity_extra_this_machine, "memoryHigh", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("memory-max", "BYTES", "Set maximum memory limit"):
                        r = parse_size_field(match_identity ?: &arg_identity_extra_this_machine, "memoryMax", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cpu-weight", "WEIGHT", "Set CPU weight"): {}
                OPTION_LONG("io-weight", "WEIGHT", "Set IO weight"): {
                        const char *field = streq(opts.opt->long_code, "cpu-weight") ? "cpuWeight" : "ioWeight";

                        r = parse_weight_field(match_identity ?: &arg_identity_extra, field, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

                OPTION_LONG("tmp-limit", "BYTES|PERCENT", "Set limit on /tmp/"): {}
                OPTION_LONG("dev-shm-limit", "BYTES|PERCENT", "Set limit on /dev/shm/"): {
                        bool is_tmp = streq(opts.opt->long_code, "tmp-limit");
                        const char *field = is_tmp ? "tmpLimit" : "devShmLimit";
                        const char *field_scale = is_tmp ? "tmpLimitScale" : "devShmLimitScale";

                        r = parse_tmpfs_limit_field(match_identity ?: &arg_identity_extra,
                                                    field, field_scale, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

                OPTION_GROUP("Storage User Record Properties"): {}

                OPTION_LONG("storage", "STORAGE",
                            "Storage type to use (luks, fscrypt, directory, subvolume, cifs)"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for field %s not valid: %s", "storage", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra_this_machine, "storage", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-path", "PATH", "Path to image file/directory"):
                        r = parse_path_field(match_identity ?: &arg_identity_extra_this_machine, "imagePath", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("drop-caches", "BOOL", "Whether to automatically drop caches on logout"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "dropCaches", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("LUKS Storage User Record Properties"): {}

                OPTION_LONG("fs-type", "TYPE",
                            "File system type to use in case of luks storage (btrfs, ext4, xfs)"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for field %s not valid: %s", "fileSystemType", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra_this_machine, "fileSystemType", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-discard", "BOOL",
                            "Whether to use 'discard' feature of file system when activated (mounted)"): {}
                OPTION_LONG("luks-offline-discard", "BOOL", "Whether to trim file on logout"): {
                        const char *field = streq(opts.opt->long_code, "luks-discard") ? "luksDiscard" : "luksOfflineDiscard";

                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, field, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

                OPTION_LONG("luks-cipher", "CIPHER", "Cipher to use for LUKS encryption"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for field %s not valid: %s", "luksCipher", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "luksCipher", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-cipher-mode", "MODE", "Cipher mode to use for LUKS encryption"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for field %s not valid: %s", "luksCipherMode", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "luksCipherMode", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-volume-key-size", "BITS", "Volume key size to use for LUKS encryption"):
                        r = parse_unsigned_field(match_identity ?: &arg_identity_extra, "luksVolumeKeySize", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-pbkdf-type", "TYPE", "Password-based Key Derivation Function to use"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for field %s not valid: %s", "luksPbkdfType", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "luksPbkdfType", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-pbkdf-hash-algorithm", "ALG", "PBKDF hash algorithm to use"):
                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Parameter for field %s not valid: %s", "luksPbkdfHashAlgorithm", opts.arg);

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "luksPbkdfHashAlgorithm", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-pbkdf-time-cost", "SECS", "Time cost for PBKDF in seconds"):
                        r = parse_time_field(match_identity ?: &arg_identity_extra, "luksPbkdfTimeCostUSec", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-pbkdf-memory-cost", "BYTES", "Memory cost for PBKDF in bytes"):
                        r = parse_size_field(match_identity ?: &arg_identity_extra_this_machine, "luksPbkdfMemoryCost", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-pbkdf-parallel-threads", "N", "Number of parallel threads for PKBDF"):
                        r = parse_unsigned_field(match_identity ?: &arg_identity_extra, "luksPbkdfParallelThreads", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-sector-size", "BYTES", "Sector size for LUKS encryption in bytes"):
                        r = parse_sector_size_field(match_identity ?: &arg_identity_extra, "luksSectorSize", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-extra-mount-options", "…", "LUKS extra mount options"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "luksExtraMountOptions", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("luks-pbkdf-force-iterations", "NUMBER", /* help= */ NULL):
                        r = parse_unsigned_field(match_identity ?: &arg_identity_extra, "luksPbkdfForceIterations", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("auto-resize-mode", "MODE",
                            "Automatically grow/shrink home on login/logout"):
                        r = parse_auto_resize_mode_field(match_identity ?: &arg_identity_extra,
                                                         "autoResizeMode", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("rebalance-weight", "WEIGHT", "Weight while rebalancing"):
                        r = parse_rebalance_weight(match_identity ?: &arg_identity_extra,
                                                   "rebalanceWeight", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Mounting User Record Properties"): {}

                OPTION_LONG("nosuid", "BOOL", "Control the 'nosuid' flag of the home mount"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "mountNoSuid", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("nodev", "BOOL", "Control the 'nodev' flag of the home mount"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "mountNoDevices", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("noexec", "BOOL", "Control the 'noexec' flag of the home mount"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "mountNoExecute", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("CIFS User Record Properties"): {}

                OPTION_LONG("cifs-domain", "DOMAIN", "CIFS (Windows) domain"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "cifsDomain", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cifs-user-name", "USER", "CIFS (Windows) user name"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "cifsUserName", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cifs-service", "SERVICE",
                            "CIFS (Windows) service to mount as home area"):
                        if (!isempty(opts.arg)) {
                                r = parse_cifs_service(opts.arg, /* ret_host= */ NULL, /* ret_service= */ NULL, /* ret_path= */ NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to validate CIFS service name: %s", opts.arg);
                        }

                        r = parse_string_field(match_identity ?: &arg_identity_extra, "cifsService", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("cifs-extra-mount-options", "…",
                            "CIFS (Windows) extra mount options"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "cifsExtraMountOptions", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Login Behaviour User Record Properties"): {}

                OPTION_LONG("stop-delay", "SECS",
                            "How long to leave user services running after logout"):
                        r = parse_time_field(match_identity ?: &arg_identity_extra, "stopDelayUSec", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("kill-processes", "BOOL",
                            "Whether to kill user processes when sessions terminate"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "killProcesses", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("auto-login", "BOOL", "Try to log this user in automatically"):
                        r = parse_boolean_field(match_identity ?: &arg_identity_extra, "autoLogin", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("session-launcher", "LAUNCHER", "Preferred session launcher file"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "preferredSessionLauncher", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("session-type", "TYPE", "Preferred session type"):
                        r = parse_string_field(match_identity ?: &arg_identity_extra, "preferredSessionType", opts.arg);
                        if (r < 0)
                                return r;
                        break;

                /* Hidden options below */

                OPTION_LONG("fido2-credential-algorithm", "ALG", /* help= */ NULL):
                        r = parse_fido2_algorithm(opts.arg, &arg_fido2_cred_alg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse COSE algorithm: %s", opts.arg);
                        break;

                OPTION_LONG("match", "any|this|other|auto", /* help= */ NULL):
                        if (streq(opts.arg, "any"))
                                match_identity = &arg_identity_extra;
                        else if (streq(opts.arg, "this"))
                                match_identity = &arg_identity_extra_this_machine;
                        else if (streq(opts.arg, "other"))
                                match_identity = &arg_identity_extra_other_machines;
                        else if (streq(opts.arg, "auto"))
                                match_identity = NULL;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--machine= argument not understood. Refusing.");
                        break;

                OPTION_SHORT('A', NULL, /* help= */ NULL):
                        match_identity = &arg_identity_extra;
                        break;

                OPTION_SHORT('T', NULL, /* help= */ NULL):
                        match_identity = &arg_identity_extra_this_machine;
                        break;

                OPTION_SHORT('N', NULL, /* help= */ NULL):
                        match_identity = &arg_identity_extra_other_machines;
                        break;
                }

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

        *remaining_args = option_parser_get_args(&opts);
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

                r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE|SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
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
        char **args = NULL;
        int r;

        log_setup();

        r = redirect_bus_mgr();
        if (r < 0)
                return r;

        if (is_fallback_shell(argv[0]))
                return fallback_shell(argc, argv);

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb_with_args(args, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
