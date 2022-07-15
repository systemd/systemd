/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <unistd.h>

#include "ask-password-api.h"
#include "def.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "strv.h"
#include "terminal-util.h"

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

STATIC_DESTRUCTOR_REGISTER(arg_message, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-ask-password", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] MESSAGE\n\n"
               "%3$sQuery the user for a system passphrase, via the TTY or an UI agent.%4$s\n\n"
               "  -h --help           Show this help\n"
               "     --icon=NAME      Icon name\n"
               "     --id=ID          Query identifier (e.g. \"cryptsetup:/dev/sda5\")\n"
               "     --keyname=NAME   Kernel key name for caching passwords (e.g. \"cryptsetup\")\n"
               "     --credential=NAME\n"
               "                      Credential name for LoadCredential=/SetCredential=\n"
               "                      credentials\n"
               "     --timeout=SEC    Timeout in seconds\n"
               "     --echo=yes|no|masked\n"
               "                      Control whether to show password while typing (echo)\n"
               "  -e --echo           Equivalent to --echo=yes\n"
               "     --emoji=yes|no|auto\n"
               "                      Show a lock and key emoji\n"
               "     --no-tty         Ask question via agent even on TTY\n"
               "     --accept-cached  Accept cached passwords\n"
               "     --multiple       List multiple passwords if available\n"
               "     --no-output      Do not print password to standard output\n"
               "  -n                  Do not suffix password written to standard output with\n"
               "                      newline\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_ICON = 0x100,
                ARG_TIMEOUT,
                ARG_EMOJI,
                ARG_NO_TTY,
                ARG_ACCEPT_CACHED,
                ARG_MULTIPLE,
                ARG_ID,
                ARG_KEYNAME,
                ARG_NO_OUTPUT,
                ARG_VERSION,
                ARG_CREDENTIAL,
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                { "icon",          required_argument, NULL, ARG_ICON          },
                { "timeout",       required_argument, NULL, ARG_TIMEOUT       },
                { "echo",          optional_argument, NULL, 'e'               },
                { "emoji",         required_argument, NULL, ARG_EMOJI         },
                { "no-tty",        no_argument,       NULL, ARG_NO_TTY        },
                { "accept-cached", no_argument,       NULL, ARG_ACCEPT_CACHED },
                { "multiple",      no_argument,       NULL, ARG_MULTIPLE      },
                { "id",            required_argument, NULL, ARG_ID            },
                { "keyname",       required_argument, NULL, ARG_KEYNAME       },
                { "no-output",     no_argument,       NULL, ARG_NO_OUTPUT     },
                { "credential",    required_argument, NULL, ARG_CREDENTIAL    },
                {}
        };

        const char *emoji = NULL;
        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* Note the asymmetry: the long option --echo= allows an optional argument, the short option does
         * not. */
        while ((c = getopt_long(argc, argv, "+hen", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_ICON:
                        arg_icon = optarg;
                        break;

                case ARG_TIMEOUT:
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter: %s", optarg);

                        break;

                case 'e':
                        if (!optarg) {
                                /* Short option -e is used, or no argument to long option --echo= */
                                arg_flags |= ASK_PASSWORD_ECHO;
                                arg_flags &= ~ASK_PASSWORD_SILENT;
                        } else if (isempty(optarg) || streq(optarg, "masked"))
                                /* Empty argument or explicit string "masked" for default behaviour. */
                                arg_flags &= ~(ASK_PASSWORD_ECHO|ASK_PASSWORD_SILENT);
                        else {
                                bool b;

                                r = parse_boolean_argument("--echo=", optarg, &b);
                                if (r < 0)
                                        return r;

                                SET_FLAG(arg_flags, ASK_PASSWORD_ECHO, b);
                                SET_FLAG(arg_flags, ASK_PASSWORD_SILENT, !b);
                        }
                        break;

                case ARG_EMOJI:
                        emoji = optarg;
                        break;

                case ARG_NO_TTY:
                        arg_flags |= ASK_PASSWORD_NO_TTY;
                        break;

                case ARG_ACCEPT_CACHED:
                        arg_flags |= ASK_PASSWORD_ACCEPT_CACHED;
                        break;

                case ARG_MULTIPLE:
                        arg_multiple = true;
                        break;

                case ARG_ID:
                        arg_id = optarg;
                        break;

                case ARG_KEYNAME:
                        arg_key_name = optarg;
                        break;

                case ARG_NO_OUTPUT:
                        arg_no_output = true;
                        break;

                case ARG_CREDENTIAL:
                        arg_credential_name = optarg;
                        break;

                case 'n':
                        arg_newline = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (isempty(emoji) || streq(emoji, "auto"))
                SET_FLAG(arg_flags, ASK_PASSWORD_HIDE_EMOJI, FLAGS_SET(arg_flags, ASK_PASSWORD_ECHO));
        else {
                bool b;

                r = parse_boolean_argument("--emoji=", emoji, &b);
                if (r < 0)
                         return r;

                SET_FLAG(arg_flags, ASK_PASSWORD_HIDE_EMOJI, !b);
        }

        if (argc > optind) {
                arg_message = strv_join(argv + optind, " ");
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

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_strv_free_erase_ char **l = NULL;
        usec_t timeout;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_timeout > 0)
                timeout = usec_add(now(CLOCK_MONOTONIC), arg_timeout);
        else
                timeout = 0;

        r = ask_password_auto(arg_message, arg_icon, arg_id, arg_key_name, arg_credential_name ?: "password", timeout, arg_flags, &l);
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
