/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "bus-polkit.h"
#include "constants.h"
#include "format-table.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "varlink-io.systemd.AskPassword.h"
#include "varlink-util.h"

static const char *arg_icon = NULL;
static const char *arg_id = NULL;               /* identifier for 'ask-password' protocol */
static const char *arg_key_name = NULL;         /* name in kernel keyring */
static const char *arg_credential_name = NULL;  /* name in $CREDENTIALS_DIRECTORY directory */
static char *arg_message = NULL;
static usec_t arg_timeout = DEFAULT_TIMEOUT_USEC;
static bool arg_multiple = false;
static bool arg_no_output = false;
static AskPasswordFlags arg_flags = ASK_PASSWORD_PUSH_CACHE;
static bool arg_newline = true;
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_message, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-ask-password", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...] MESSAGE\n"
               "\n%sQuery the user for a passphrase, via the TTY or a UI agent.%s\n"
               "\nOptions:\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());
        table_print(options, stdout);

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        const char *emoji = NULL;
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = {};
        const char *arg;

        FOREACH_OPTION(&state, c, argc, argv, &arg, /* on_error= */ return c)
                switch (c) {
                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("icon", "NAME", "Icon name"):
                        arg_icon = arg;
                        break;

                OPTION_LONG("timeout", "SEC", "Timeout in seconds"):
                        r = parse_sec(arg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter: %s", arg);
                        break;

                        /* Note the asymmetry: the long option --echo= allows an optional argument,
                         * the short option does not. */
                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "echo", "yes|no|masked",
                                  "Control whether to show password while typing"): {}
                OPTION('e', "echo", NULL, "Equivalent to --echo=yes"):
                        if (!arg) {
                                /* Short option -e is used, or no argument to long option --echo= */
                                arg_flags |= ASK_PASSWORD_ECHO;
                                arg_flags &= ~ASK_PASSWORD_SILENT;
                        } else if (isempty(arg) || streq(arg, "masked"))
                                /* Empty argument or explicit string "masked" for default behaviour. */
                                arg_flags &= ~(ASK_PASSWORD_ECHO|ASK_PASSWORD_SILENT);
                        else {
                                r = parse_boolean_argument("--echo=", arg, NULL);
                                if (r < 0)
                                        return r;

                                SET_FLAG(arg_flags, ASK_PASSWORD_ECHO, r);
                                SET_FLAG(arg_flags, ASK_PASSWORD_SILENT, !r);
                        }
                        break;

                OPTION_LONG("emoji", "yes|no|auto", "Show a lock and key emoji"):
                        emoji = arg;
                        break;

                OPTION_LONG("no-tty", NULL, "Ask question via agent even on TTY"):
                        arg_flags |= ASK_PASSWORD_NO_TTY;
                        break;

                OPTION_LONG("accept-cached", NULL, "Accept cached passwords"):
                        arg_flags |= ASK_PASSWORD_ACCEPT_CACHED;
                        break;

                OPTION_LONG("multiple", NULL, "List multiple passwords if available"):
                        arg_multiple = true;
                        break;

                OPTION_LONG("id", "ID", "Query identifier (e.g. \"cryptsetup:/dev/sda5\")"):
                        arg_id = arg;
                        break;

                OPTION_LONG("keyname", "NAME", "Kernel key name for caching passwords"):
                        arg_key_name = arg;
                        break;

                OPTION_LONG("no-output", NULL, "Do not print password to standard output"):
                        arg_no_output = true;
                        break;

                OPTION_LONG("credential", "NAME",
                            "Credential name for ImportCredential=, LoadCredential= or SetCredential= credentials"):
                        arg_credential_name = arg;
                        break;

                OPTION_LONG("user", NULL, "Ask only our own user's agents"):
                        arg_flags |= ASK_PASSWORD_USER;
                        break;

                OPTION_LONG("system", NULL, "Ask agents of the system and of all users"):
                        arg_flags &= ~ASK_PASSWORD_USER;
                        break;

                OPTION_SHORT('n', NULL, "Do not suffix password written to standard output with newline"):
                        arg_newline = false;
                        break;
                }

        if (isempty(emoji) || streq(emoji, "auto"))
                SET_FLAG(arg_flags, ASK_PASSWORD_HIDE_EMOJI, FLAGS_SET(arg_flags, ASK_PASSWORD_ECHO));
        else {
                r = parse_boolean_argument("--emoji=", emoji, NULL);
                if (r < 0)
                        return r;

                SET_FLAG(arg_flags, ASK_PASSWORD_HIDE_EMOJI, !r);
        }

        char **args = option_parser_get_args(&state, argc, argv);

        if (!strv_isempty(args)) {
                arg_message = strv_join(args, " ");
                if (!arg_message)
                        return log_oom();
        } else if (FLAGS_SET(arg_flags, ASK_PASSWORD_ECHO)) {
                /* By default ask_password_auto() will query with the string "Password: ", which is not right
                 * when full echo is on, since then it's unlikely a password. Let's hence default to a less
                 * confusing string in that case. */

                arg_message = strdup("Input:");
                if (!arg_message)
                        return log_oom();
        }

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;

        return 1;
}

typedef enum EchoMode {
        ECHO_OFF,
        ECHO_ON,
        ECHO_MASKED,
        _ECHO_MODE_MAX,
        _ECHO_MODE_INVALID = -EINVAL,
} EchoMode;

static const char* echo_mode_table[_ECHO_MODE_MAX] = {
        [ECHO_OFF]    = "off",
        [ECHO_ON]     = "on",
        [ECHO_MASKED] = "masked",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(echo_mode, EchoMode, ECHO_ON);

static JSON_DISPATCH_ENUM_DEFINE(dispatch_echo_mode, EchoMode, echo_mode_from_string);

typedef struct MethodAskParameters {
        const char *message;
        const char *keyring;
        const char *icon;
        const char *id;
        uint64_t timeout_usec;
        uint64_t until_usec;
        int accept_cached;
        int push_cache;
        EchoMode echo_mode;
} MethodAskParameters;

static int vl_method_ask(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "message",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MethodAskParameters, message),       SD_JSON_STRICT },
                { "keyname",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MethodAskParameters, keyring),       SD_JSON_STRICT },
                { "icon",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MethodAskParameters, icon),          SD_JSON_STRICT },
                { "id",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(MethodAskParameters, id),            SD_JSON_STRICT },
                { "timeoutUSec",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(MethodAskParameters, timeout_usec),  0              },
                { "untilUSec",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(MethodAskParameters, until_usec),    0              },
                { "acceptCached", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(MethodAskParameters, accept_cached), 0              },
                { "pushCache",    SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(MethodAskParameters, push_cache) ,   0              },
                { "echo",         SD_JSON_VARIANT_STRING,        dispatch_echo_mode,            offsetof(MethodAskParameters, echo_mode),     0              },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        MethodAskParameters p = {
                .timeout_usec = DEFAULT_TIMEOUT_USEC,
                .until_usec = UINT64_MAX,
                .accept_cached = -1,
                .push_cache = -1,
                .echo_mode = _ECHO_MODE_INVALID,
        };
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.ask-password.ask",
                        /* details= */ NULL,
                        /* good_user= */ FLAGS_SET(arg_flags, ASK_PASSWORD_USER) ? getuid() : UID_INVALID,
                        /* flags= */ 0,
                        polkit_registry);
        if (r <= 0)
                return r;

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = p.message ?: arg_message,
                .icon = p.icon ?: arg_icon,
                .id = p.id ?: arg_id,
                .keyring = p.keyring ?: arg_key_name,
                .credential = arg_credential_name,
                .hup_fd = sd_varlink_get_input_fd(link),
        };

        /* Specifying the absolute or relative timeout as zero means: do not ask interactively, only check
         * cache, hence leave the field at zero in that case. Otherwise we take the minimum of both times. */
        if (p.timeout_usec != 0 && p.until_usec != 0)
                req.until = MIN(usec_add(now(CLOCK_MONOTONIC), p.timeout_usec), p.until_usec);

        /* If the timeout is set to zero, don't ask agents, just stick to cache */
        SET_FLAG(arg_flags, ASK_PASSWORD_NO_AGENT, req.until == 0);

        if (p.accept_cached >= 0)
                SET_FLAG(arg_flags, ASK_PASSWORD_ACCEPT_CACHED, p.accept_cached);

        if (p.push_cache >= 0)
                SET_FLAG(arg_flags, ASK_PASSWORD_PUSH_CACHE, p.push_cache);

        if (p.echo_mode >= 0) {
                SET_FLAG(arg_flags, ASK_PASSWORD_ECHO, p.echo_mode == ECHO_ON);
                SET_FLAG(arg_flags, ASK_PASSWORD_SILENT, p.echo_mode == ECHO_OFF);
        }

        _cleanup_strv_free_erase_ char **l = NULL;
        r = ask_password_auto(&req, arg_flags, &l);
        if (r == -EUNATCH)
                return sd_varlink_error(link, "io.systemd.AskPassword.NoPasswordAvailable", NULL);
        if (r == -ETIME)
                return sd_varlink_error(link, "io.systemd.AskPassword.TimeoutReached", NULL);
        if (r == -ECONNRESET) { /* POLLHUP on the varlink fd we passed in via .hup_fd */
                sd_varlink_close(link);
                return 1;
        }
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *vl = NULL;
        r = sd_json_variant_new_array_strv(&vl, l);
        if (r < 0)
                return r;

        sd_json_variant_sensitive(vl);

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("passwords", vl));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        _cleanup_hashmap_free_ Hashmap *polkit_registry = NULL;
        int r;

        r = varlink_server_new(&varlink_server, SD_VARLINK_SERVER_INHERIT_USERDATA, /* userdata= */ &polkit_registry);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_AskPassword);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.AskPassword.Ask", vl_method_ask);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_strv_free_erase_ char **l = NULL;
        usec_t timeout;
        int r;

        log_setup();

        /* Unprivileged? Then imply ASK_PASSWORD_USER by default */
        SET_FLAG(arg_flags, ASK_PASSWORD_USER, geteuid() != 0);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_varlink)
                return vl_server(); /* Invocation as Varlink service */

        timeout = arg_timeout > 0 ? usec_add(now(CLOCK_MONOTONIC), arg_timeout) : 0;

        AskPasswordRequest req = {
                .tty_fd = -EBADF,
                .message = arg_message,
                .icon = arg_icon,
                .id = arg_id,
                .keyring = arg_key_name,
                .credential = arg_credential_name ?: "password",
                .until = timeout,
                .hup_fd = -EBADF,
        };

        r = ask_password_auto(&req, arg_flags, &l);
        if (r < 0)
                return log_error_errno(r, "Failed to query password: %m");

        STRV_FOREACH(p, l) {
                if (!arg_no_output) {
                        if (arg_newline)
                                puts(*p);
                        else
                                fputs(*p, stdout);
                }

                fflush(stdout);

                if (!arg_multiple)
                        break;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
