/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-varlink.h"

#include "build.h"
#include "bus-util.h"
#include "chase.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "memfd-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "runtime-scope.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "varlink-idl-util.h"
#include "varlink-util.h"
#include "verbs.h"
#include "version.h"

typedef struct PushFds {
        int *fds;
        size_t n_fds;
} PushFds;

static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static sd_varlink_method_flags_t arg_method_flags = 0;
static bool arg_collect = false;
static bool arg_quiet = false;
static char **arg_graceful = NULL;
static usec_t arg_timeout = 0;
static bool arg_exec = false;
static PushFds arg_push_fds = {};
static bool arg_ask_password = true;
static bool arg_legend = true;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

static void push_fds_done(PushFds *p) {
        assert(p);

        close_many_and_free(p->fds, p->n_fds);
        *p = (PushFds) {};
}

STATIC_DESTRUCTOR_REGISTER(arg_graceful, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_push_fds, push_fds_done);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("varlinkctl", "1", &link);
        if (r < 0)
                return log_oom();

        pager_open(arg_pager_flags);

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sIntrospect Varlink Services.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  info ADDRESS           Show service information\n"
               "  list-interfaces ADDRESS\n"
               "                         List interfaces implemented by service\n"
               "  list-methods ADDRESS [INTERFACE…]\n"
               "                         List methods implemented by services or specific\n"
               "                         interfaces\n"
               "  introspect ADDRESS [INTERFACE…]\n"
               "                         Show interface definition\n"
               "  call ADDRESS METHOD [PARAMS]\n"
               "                         Invoke method\n"
               "  --exec call ADDRESS METHOD PARAMS -- CMDLINE…\n"
               "                         Invoke method and pass response and fds to command\n"
               "  list-registry          Show list of services in the service registry\n"
               "  validate-idl [FILE]    Validate interface description\n"
               "  help                   Show this help\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-ask-password   Do not prompt for password\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --system            Enumerate system registry\n"
               "     --user              Enumerate user registry\n"
               "     --more              Request multiple responses\n"
               "     --collect           Collect multiple responses in a JSON array\n"
               "     --oneway            Do not request response\n"
               "     --json=MODE         Output as JSON\n"
               "  -j                     Same as --json=pretty on tty, --json=short otherwise\n"
               "  -q --quiet             Do not output method reply\n"
               "     --graceful=ERROR    Treat specified Varlink error as success\n"
               "     --timeout=SECS      Maximum time to wait for method call completion\n"
               "  -E                     Short for --more --timeout=infinity\n"
               "     --push-fd=FD        Pass the specified fd along with method call\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_MORE,
                ARG_ONEWAY,
                ARG_JSON,
                ARG_COLLECT,
                ARG_GRACEFUL,
                ARG_TIMEOUT,
                ARG_EXEC,
                ARG_PUSH_FD,
                ARG_NO_ASK_PASSWORD,
                ARG_USER,
                ARG_SYSTEM,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "more",            no_argument,       NULL, ARG_MORE            },
                { "oneway",          no_argument,       NULL, ARG_ONEWAY          },
                { "json",            required_argument, NULL, ARG_JSON            },
                { "collect",         no_argument,       NULL, ARG_COLLECT         },
                { "quiet",           no_argument,       NULL, 'q'                 },
                { "graceful",        required_argument, NULL, ARG_GRACEFUL        },
                { "timeout",         required_argument, NULL, ARG_TIMEOUT         },
                { "exec",            no_argument,       NULL, ARG_EXEC            },
                { "push-fd",         required_argument, NULL, ARG_PUSH_FD         },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "user",            no_argument,       NULL, ARG_USER            },
                { "system",          no_argument,       NULL, ARG_SYSTEM          },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hjqE", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case 'E':
                        arg_timeout = USEC_INFINITY;
                        _fallthrough_;

                case ARG_MORE:
                        arg_method_flags = (arg_method_flags & ~SD_VARLINK_METHOD_ONEWAY) | SD_VARLINK_METHOD_MORE;
                        break;

                case ARG_ONEWAY:
                        arg_method_flags = (arg_method_flags & ~SD_VARLINK_METHOD_MORE) | SD_VARLINK_METHOD_ONEWAY;
                        break;

                case ARG_COLLECT:
                        arg_collect = true;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_GRACEFUL:
                        r = varlink_idl_qualified_symbol_name_is_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to validate Varlink error name '%s': %m", optarg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid Varlink error name: %s", optarg);

                        if (strv_extend(&arg_graceful, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_TIMEOUT:
                        if (isempty(optarg)) {
                                arg_timeout = USEC_INFINITY;
                                break;
                        }

                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter '%s': %m", optarg);

                        if (arg_timeout == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Timeout cannot be zero.");

                        break;

                case ARG_EXEC:
                        arg_exec = true;
                        break;

                case ARG_PUSH_FD: {
                        if (!GREEDY_REALLOC(arg_push_fds.fds, arg_push_fds.n_fds + 1))
                                return log_oom();

                        _cleanup_close_ int add_fd = -EBADF;
                        if (STARTSWITH_SET(optarg, "/", "./")) {
                                /* We usually expect a numeric fd spec, but as an extension let's treat this
                                 * as a path to open in read-only mode in case this is clearly an absolute or
                                 * relative path */
                                add_fd = open(optarg, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                                if (add_fd < 0)
                                        return log_error_errno(errno, "Failed to open '%s': %m", optarg);
                        } else {
                                int parsed_fd = parse_fd(optarg);
                                if (parsed_fd < 0)
                                        return log_error_errno(parsed_fd, "Failed to parse --push-fd= parameter: %s", optarg);

                                /* Make a copy, so that the same fd could be used multiple times in a reasonable
                                 * way. This also validates the fd early */
                                add_fd = fcntl(parsed_fd, F_DUPFD_CLOEXEC, 3);
                                if (add_fd < 0)
                                        return log_error_errno(errno, "Failed to duplicate file descriptor %i: %m", parsed_fd);
                        }

                        arg_push_fds.fds[arg_push_fds.n_fds++] = TAKE_FD(add_fd);
                        break;
                }

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* If more than one reply is expected, imply JSON-SEQ output, and set SD_JSON_FORMAT_FLUSH */
        if (FLAGS_SET(arg_method_flags, SD_VARLINK_METHOD_MORE))
                arg_json_format_flags |= SD_JSON_FORMAT_SEQ|SD_JSON_FORMAT_FLUSH;

        strv_sort_uniq(arg_graceful);

        return 1;
}

static int varlink_connect_auto(sd_varlink **ret, const char *where) {
        int r;

        assert(ret);
        assert(where);

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;

        if (STARTSWITH_SET(where, "/", "./")) { /* If the string starts with a slash or dot slash we use it as a file system path */
                _cleanup_close_ int fd = -EBADF;
                struct stat st;

                fd = open(where, O_PATH|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", where);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", where);

                if (S_ISSOCK(st.st_mode)) {
                        /* Is this a socket in the fs? Then connect() to it. */

                        r = sd_varlink_connect_address(&vl, FORMAT_PROC_FD_PATH(fd));
                        if (r < 0)
                                return log_error_errno(r, "Failed to connect to '%s': %m", where);

                } else if (S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
                        /* Is this an executable binary? Then fork it off. */

                        r = sd_varlink_connect_exec(&vl, where, STRV_MAKE(where)); /* Ideally we'd use FORMAT_PROC_FD_PATH(fd) here too, but that breaks the #! logic */
                        if (r < 0)
                                return log_error_errno(r, "Failed to spawn '%s' process: %m", where);
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unrecognized path '%s' is neither an AF_UNIX socket, nor an executable binary.", where);
        } else {
                /* Otherwise assume this is an URL */
                r = sd_varlink_connect_url(&vl, where);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to URL '%s': %m", where);
        }

        if (arg_timeout != 0) {
                r = sd_varlink_set_relative_timeout(vl, arg_timeout);
                if (r < 0)
                        log_warning_errno(r, "Failed to set Varlink timeout, ignoring: %m");
        }

        *ret = TAKE_PTR(vl);
        return 0;
}

typedef struct GetInfoData {
        const char *vendor;
        const char *product;
        const char *version;
        const char *url;
        char **interfaces;
} GetInfoData;

static void get_info_data_done(GetInfoData *d) {
        assert(d);

        d->interfaces = strv_free(d->interfaces);
}

static int verb_info(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        const char *url;
        int r;

        assert(argc == 2);
        url = argv[1];

        r = varlink_connect_auto(&vl, url);
        if (r < 0)
                return r;

        sd_json_variant *reply = NULL;
        r = varlink_call_and_log(vl, "org.varlink.service.GetInfo", /* parameters= */ NULL, &reply);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                static const sd_json_dispatch_field dispatch_table[] = {
                        { "vendor",     SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(GetInfoData, vendor),     SD_JSON_MANDATORY },
                        { "product",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(GetInfoData, product),    SD_JSON_MANDATORY },
                        { "version",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(GetInfoData, version),    SD_JSON_MANDATORY },
                        { "url",        SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(GetInfoData, url),        SD_JSON_MANDATORY },
                        { "interfaces", SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_strv,         offsetof(GetInfoData, interfaces), SD_JSON_MANDATORY },
                        {}
                };
                _cleanup_(get_info_data_done) GetInfoData data = {};

                r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &data);
                if (r < 0)
                        return r;

                strv_sort(data.interfaces);

                if (streq_ptr(argv[0], "list-interfaces")) {
                        STRV_FOREACH(i, data.interfaces)
                                puts(*i);
                } else {
                        _cleanup_(table_unrefp) Table *t = NULL;

                        t = table_new_vertical();
                        if (!t)
                                return log_oom();

                        r = table_add_many(
                                        t,
                                        TABLE_FIELD, "Vendor",
                                        TABLE_STRING, data.vendor,
                                        TABLE_FIELD, "Product",
                                        TABLE_STRING, data.product,
                                        TABLE_FIELD, "Version",
                                        TABLE_STRING, data.version,
                                        TABLE_FIELD, "URL",
                                        TABLE_STRING, data.url,
                                        TABLE_SET_URL, data.url,
                                        TABLE_FIELD, "Interfaces",
                                        TABLE_STRV, data.interfaces);
                        if (r < 0)
                                return table_log_add_error(r);

                        r = table_print(t, NULL);
                        if (r < 0)
                                return table_log_print_error(r);
                }
        } else {
                sd_json_variant *v;

                v = streq_ptr(argv[0], "list-interfaces") ?
                        sd_json_variant_by_key(reply, "interfaces") : reply;

                sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
        }

        return 0;
}

static size_t break_columns(void) {
        int r;

        /* Rebreak the interface data to the TTY width */
        if (on_tty())
                return columns();

        /* if not connected to a tty, still allow the caller to control the columns via the usual env var */
        r = getenv_columns();
        if (r < 0)
                return SIZE_MAX;

        return r;
}

typedef struct GetInterfaceDescriptionData {
        const char *description;
} GetInterfaceDescriptionData;

static int verb_introspect(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_strv_free_ char **auto_interfaces = NULL;
        char **interfaces;
        const char *url;
        bool list_methods;
        int r;

        assert(argc >= 2);
        list_methods = streq(argv[0], "list-methods");
        url = argv[1];
        interfaces = strv_skip(argv, 2);

        STRV_FOREACH(i, interfaces)
                if (!varlink_idl_interface_name_is_valid(*i))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid Varlink interface name: '%s'", *i);

        r = varlink_connect_auto(&vl, url);
        if (r < 0)
                return r;

        if (strv_isempty(interfaces)) {
                sd_json_variant *reply = NULL;

                /* If no interface is specified, introspect all of them */

                r = varlink_call_and_log(vl, "org.varlink.service.GetInfo", /* parameters= */ NULL, &reply);
                if (r < 0)
                        return r;

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "interfaces", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_strv, 0, SD_JSON_MANDATORY },
                        {}
                };

                r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &auto_interfaces);
                if (r < 0)
                        return r;

                if (strv_isempty(auto_interfaces))
                        return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Service doesn't report any implemented interfaces.");

                interfaces = strv_sort_uniq(auto_interfaces);
        }

        /* Automatically switch on JSON_SEQ if we output multiple JSON objects */
        if (!list_methods && strv_length(interfaces) > 1)
                arg_json_format_flags |= SD_JSON_FORMAT_SEQ;

        _cleanup_strv_free_ char **methods = NULL;

        STRV_FOREACH(i, interfaces) {
                sd_json_variant *reply = NULL;
                r = varlink_callbo_and_log(
                                vl,
                                "org.varlink.service.GetInterfaceDescription",
                                &reply,
                                SD_JSON_BUILD_PAIR_STRING("interface", *i));
                if (r < 0)
                        return r;

                if (!sd_json_format_enabled(arg_json_format_flags) || list_methods) {
                        static const sd_json_dispatch_field dispatch_table[] = {
                                { "description", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                                {}
                        };
                        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *vi = NULL;
                        const char *description = NULL;
                        unsigned line = 0, column = 0;

                        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &description);
                        if (r < 0)
                                return r;

                        if (!list_methods && i > interfaces)
                                print_separator();

                        /* Try to parse the returned description, so that we can add syntax highlighting */
                        r = sd_varlink_idl_parse(ASSERT_PTR(description), &line, &column, &vi);
                        if (r < 0) {
                                if (list_methods)
                                        return log_error_errno(r, "Failed to parse returned interface description at %u:%u: %m", line, column);

                                log_warning_errno(r, "Failed to parse returned interface description at %u:%u, showing raw interface description: %m", line, column);

                                pager_open(arg_pager_flags);
                                fputs_with_newline(stdout, description);
                        } else if (list_methods) {
                                for (const sd_varlink_symbol *const *y = vi->symbols, *symbol; (symbol = *y); y++) {
                                        if (symbol->symbol_type != SD_VARLINK_METHOD)
                                                continue;

                                        r = strv_extendf(&methods, "%s.%s", vi->name, symbol->name);
                                        if (r < 0)
                                                return log_oom();
                                }
                        } else {
                                pager_open(arg_pager_flags);
                                r = sd_varlink_idl_dump(stdout, vi, SD_VARLINK_IDL_FORMAT_COLOR_AUTO, break_columns());
                                if (r < 0)
                                        return log_error_errno(r, "Failed to format parsed interface description: %m");
                        }
                } else {
                        pager_open(arg_pager_flags);
                        sd_json_variant_dump(reply, arg_json_format_flags, stdout, NULL);
                }
        }

        if (list_methods) {
                pager_open(arg_pager_flags);

                strv_sort_uniq(methods);

                if (!sd_json_format_enabled(arg_json_format_flags))
                        strv_print(methods);
                else {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;

                        r = sd_json_build(&j, SD_JSON_BUILD_STRV(methods));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON array: %m");

                        sd_json_variant_dump(j, arg_json_format_flags, stdout, NULL);
                }
        }

        return 0;
}

static int reply_callback(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error,
                sd_varlink_reply_flags_t flags,
                void *userdata)  {

        int *ret = ASSERT_PTR(userdata), r;

        assert(link);

        if (error) {
                /* Propagate the error we received via sd_notify() */
                (void) sd_notifyf(/* unset_environment= */ false, "VARLINKERROR=%s", error);

                if (strv_contains(arg_graceful, error)) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                 "Method call returned expected error: %s", error);

                        r = 0;
                } else {
                        /* If we can translate this to an errno, let's print that as errno and return it, otherwise, return a generic error code */
                        r = sd_varlink_error_to_errno(error, parameters);
                        if (r != -EBADR)
                                *ret = log_error_errno(r, "Method call failed: %m");
                        else
                                r = *ret = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call failed: %s", error);
                }
        } else {
                /* Let the caller know we have received at least one reply now. This is useful for
                 * subscription style interfaces where the first reply indicates the subscription being
                 * successfully enabled. */
                (void) sd_notify(/* unset_environment= */ false, "READY=1");
                r = 0;
        }

        if (!arg_quiet)
                sd_json_variant_dump(parameters, arg_json_format_flags, stdout, NULL);

        return r;
}

static int verb_call(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jp = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        const char *url, *method, *parameter, *source;
        char **cmdline;
        int r;

        assert(argc >= 3);

        if (argc > 4 && !arg_exec)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");
        if (arg_exec && argc < 5)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected command line to execute.");

        if (arg_exec && (arg_collect || (arg_method_flags & (SD_VARLINK_METHOD_ONEWAY|SD_VARLINK_METHOD_MORE))) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--exec and --collect/--more/--oneway may not be combined.");

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        url = argv[1];
        method = argv[2];
        parameter = argc > 3 && !streq(argv[3], "-") ? argv[3] : NULL;
        cmdline = strv_skip(argv, 4);

        /* No JSON mode explicitly configured? Then default to the same as -j (except if --exec is used, in
         * which case generate shortest possible JSON since we are going to pass it to a program rather than
         * a user anyway) */
        if (!sd_json_format_enabled(arg_json_format_flags)) {
                arg_json_format_flags &= ~SD_JSON_FORMAT_OFF;

                if (arg_exec)
                        arg_json_format_flags |= SD_JSON_FORMAT_NEWLINE;
                else
                        arg_json_format_flags |= SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
        }

        /* For pipeable text tools it's kinda customary to finish output off in a newline character, and not
         * leave incomplete lines hanging around. */
        arg_json_format_flags |= SD_JSON_FORMAT_NEWLINE;

        if (!varlink_idl_qualified_symbol_name_is_valid(method))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid qualified method name: '%s' (Expected valid Varlink interface name, followed by a dot, followed by a valid Varlink symbol name.)", method);

        unsigned line = 0, column = 0;
        if (parameter) {
                source = "<argv[4]>";

                /* <argv[4]> is correct, as dispatch_verb() shifts arguments by one for the verb. */
                r = sd_json_parse_with_source(parameter, source, 0, &jp, &line, &column);
        } else {
                if (isatty_safe(STDIN_FILENO) && !arg_quiet)
                        log_notice("Expecting method call parameter JSON object on standard input. (Provide empty string or {} for no parameters.)");

                source = "<stdin>";

                r = sd_json_parse_file_at(stdin, AT_FDCWD, source, 0, &jp, &line, &column);
        }
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to parse parameters at %s:%u:%u: %m", source, line, column);

        /* If parsing resulted in ENODATA the provided string was empty. As convenience to users we'll accept
         * that and treat it as equivalent to an empty object: as a call with empty set of parameters. This
         * mirrors how we do this in our C APIs too, where we are happy to accept NULL instead of a proper
         * JsonVariant object for method calls. */

        r = varlink_connect_auto(&vl, url);
        if (r < 0)
                return r;

        if (arg_push_fds.n_fds > 0) {
                r = sd_varlink_set_allow_fd_passing_output(vl, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable fd passing: %m");

                FOREACH_ARRAY(f, arg_push_fds.fds, arg_push_fds.n_fds) {
                        r = sd_varlink_push_fd(vl, *f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to push file descriptor: %m");

                        TAKE_FD(*f); /* we passed ownership away */
                }
        }

        if (arg_collect) {
                sd_json_variant *reply = NULL;
                const char *error = NULL;

                r = sd_varlink_collect(vl, method, jp, &reply, &error);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);
                if (error) {
                        /* Propagate the error we received via sd_notify() */
                        (void) sd_notifyf(/* unset_environment= */ false, "VARLINKERROR=%s", error);

                        if (strv_contains(arg_graceful, error)) {
                                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                         "Method call %s() returned expected error: %s", method, error);

                                r = 0;
                        } else {
                                r = sd_varlink_error_to_errno(error, reply);
                                if (r != -EBADR)
                                        log_error_errno(r, "Method call %s() failed: %m", method);
                                else
                                        r = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call %s() failed: %s", method, error);
                        }
                } else
                        r = 0;

                if (arg_quiet)
                        return r;

                pager_open(arg_pager_flags);
                sd_json_variant_dump(reply, arg_json_format_flags, stdout, NULL);
                return r;

        } else if (arg_method_flags & SD_VARLINK_METHOD_ONEWAY) {
                r = sd_varlink_send(vl, method, jp);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);

                r = sd_varlink_flush(vl);
                if (r < 0)
                        return log_error_errno(r, "Failed to flush Varlink connection: %m");

        } else if (arg_method_flags & SD_VARLINK_METHOD_MORE) {

                int ret = 0;
                sd_varlink_set_userdata(vl, &ret);

                r = sd_varlink_bind_reply(vl, reply_callback);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind reply callback: %m");

                r = sd_varlink_observe(vl, method, jp);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);

                for (;;) {
                        r = sd_varlink_is_idle(vl);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check if varlink connection is idle: %m");
                        if (r > 0)
                                break;

                        r = sd_varlink_process(vl);
                        if (r < 0)
                                return log_error_errno(r, "Failed to process varlink connection: %m");
                        if (r != 0)
                                continue;

                        r = sd_varlink_wait(vl, USEC_INFINITY);
                        if (r < 0)
                                return log_error_errno(r, "Failed to wait for varlink connection events: %m");
                }

                return ret;
        } else {
                sd_json_variant *reply = NULL;
                const char *error = NULL;
                bool process_fds = false;

                if (arg_exec) {
                        r = sd_varlink_set_allow_fd_passing_input(vl, true);
                        if (r < 0)
                                log_debug_errno(r, "Unable to enable file descriptor receiving, ignoring: %m");
                        else
                                process_fds = true;
                }

                r = sd_varlink_call(vl, method, jp, &reply, &error);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);

                /* If the server returned an error to us, then fail, but first output the associated parameters */
                if (error) {
                        /* Propagate the error we received via sd_notify() */
                        (void) sd_notifyf(/* unset_environment= */ false, "VARLINKERROR=%s", error);

                        if (strv_contains(arg_graceful, error)) {
                                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                         "Method call %s() returned expected error: %s", method, error);

                                r = 0;
                        } else if (streq(error, SD_VARLINK_ERROR_EXPECTED_MORE))
                                r = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call %s() failed: called without 'more' flag, but flag needs to be set.", method);
                        else {
                                r = sd_varlink_error_to_errno(error, reply);
                                if (r != -EBADR)
                                        log_error_errno(r, "Method call %s() failed: %m", method);
                                else
                                        r = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call %s() failed: %s", method, error);
                        }
                } else
                        r = 0;

                if (arg_exec && r == 0) {
                        (void) sd_notify(/* unset_environment= */ false, "READY=1");

                        _cleanup_free_ char *formatted = NULL;
                        r = sd_json_variant_format(reply, arg_json_format_flags, &formatted);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format reply: %m");

                        _cleanup_close_ int mfd = memfd_new_and_seal_string("varlink-reply", formatted);
                        if (mfd < 0)
                                return log_error_errno(mfd, "Failed to allocate memfd for reply: %m");

                        _cleanup_free_ char *j = strv_join(cmdline, " ");
                        if (!j)
                                return log_oom();

                        int *fd_array = NULL, n = 0;
                        size_t m = 0;
                        CLEANUP_ARRAY(fd_array, m, close_many_and_free);

                        if (process_fds) {
                                n = sd_varlink_get_n_fds(vl);
                                if (n < 0)
                                        return log_error_errno(n, "Failed to determine how many file descriptors we received: %m");

                                fd_array = new(int, n);
                                if (!fd_array)
                                        return log_oom();

                                for (int i = 0; i < n; i++) {
                                        fd_array[m] = sd_varlink_take_fd(vl, i);
                                        if (fd_array[m] < 0)
                                                return log_error_errno(fd_array[m], "Failed to acquire fd we received: %m");

                                        m++;
                                }
                        }

                        /* We'll now close all remaining fds. This means we are stealing other code that
                         * lives in our process their fds. Hence we will now no longer bubble up any
                         * errors. */

                        log_close();
                        log_set_open_when_needed(true);

                        r = move_fd(mfd, STDIN_FILENO, /* cloexec= */ false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to move reply to STDIN_FILENO: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = close_all_fds(fd_array, m);
                        if (r < 0) {
                                log_error_errno(r, "Failed to close all remaining file descriptors: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = pack_fds(fd_array, m);
                        if (r < 0) {
                                log_error_errno(r, "Failed to rearrange file descriptors: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = fd_cloexec_many(fd_array, m, false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to disable O_CLOEXEC for file descriptors: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (m > 0) {
                                r = setenvf("LISTEN_FDS", /* overwrite= */ true, "%zu", m);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to set $LISTEN_FDS environment variable: %m");
                                        _exit(EXIT_FAILURE);
                                }

                                r = setenvf("LISTEN_PID", /* overwrite= */ true, PID_FMT, getpid_cached());
                                if (r < 0) {
                                        log_error_errno(r, "Failed to set $LISTEN_PID environment variable: %m");
                                        _exit(EXIT_FAILURE);
                                }

                                uint64_t pidfdid;
                                if (pidfd_get_inode_id_self_cached(&pidfdid) >= 0) {
                                        r = setenvf("LISTEN_PIDFDID", /* overwrite= */ true, "%" PRIu64, pidfdid);
                                        if (r < 0) {
                                                log_error_errno(r, "Failed to set $LISTEN_PIDFDID environment variable: %m");
                                                _exit(EXIT_FAILURE);
                                        }
                                }
                        } else {
                                (void) unsetenv("LISTEN_FDS");
                                (void) unsetenv("LISTEN_PID");
                                (void) unsetenv("LISTEN_PIDFDID");
                        }
                        (void) unsetenv("LISTEN_FDNAMES");

                        log_debug("Executing: %s", j);

                        execvp(cmdline[0], cmdline);
                        log_error_errno(errno, "Failed to execute '%s': %m", j);
                        _exit(EXIT_FAILURE);
                }

                if (arg_quiet)
                        return r;

                pager_open(arg_pager_flags);

                sd_json_variant_dump(reply, arg_json_format_flags, stdout, NULL);
                return r;
        }

        return 0;
}

static int verb_validate_idl(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *vi = NULL;
        _cleanup_free_ char *text = NULL;
        const char *fname;
        unsigned line = 1, column = 1;
        int r;

        fname = argc > 1 ? argv[1] : NULL;

        if (fname) {
                r = read_full_file(fname, &text, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read interface description file '%s': %m", fname);
        } else {
                r = read_full_stream(stdin, &text, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read interface description from stdin: %m");

                fname = "<stdin>";
        }

        r = sd_varlink_idl_parse(text, &line, &column, &vi);
        if (r == -EBADMSG)
                return log_error_errno(r, "%s:%u:%u: Bad syntax.", fname, line, column);
        if (r == -ENETUNREACH)
                return log_error_errno(r, "%s:%u:%u: Failed to parse interface description due an unresolved type.", fname, line, column);
        if (r < 0)
                return log_error_errno(r, "%s:%u:%u: Failed to parse interface description: %m", fname, line, column);

        r = varlink_idl_consistent(vi, LOG_ERR);
        if (r == -EUCLEAN)
                return log_error_errno(r, "Interface is inconsistent.");
        if (r == -ENOTUNIQ)
                return log_error_errno(r, "Field or symbol not unique in interface.");
        if (r < 0)
                return log_error_errno(r, "Failed to check interface for consistency: %m");

        if (arg_quiet)
                return 0;

        pager_open(arg_pager_flags);

        r = sd_varlink_idl_dump(stdout, vi, SD_VARLINK_IDL_FORMAT_COLOR_AUTO, break_columns());
        if (r < 0)
                return log_error_errno(r, "Failed to format parsed interface description: %m");

        return 0;
}

static int verb_list_registry(int argc, char *argv[], void *userdata) {
        int r;

        assert(argc <= 1);

        _cleanup_free_ char *reg_path = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "varlink/registry", &reg_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine registry path: %m");

        _cleanup_(table_unrefp) Table *table = table_new("interface", "entrypoint");
        if (!table)
                return log_oom();

        (void) table_set_sort(table, (size_t) 0);

        _cleanup_close_ int regfd = open(reg_path, O_DIRECTORY|O_CLOEXEC);
        if (regfd < 0)  {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open '%s': %m", reg_path);
        } else {
                _cleanup_free_ DirectoryEntries *des = NULL;
                r = readdir_all(regfd, RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &des);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate '%s': %m", reg_path);

                FOREACH_ARRAY(i, des->entries, des->n_entries) {
                        struct dirent *de = *i;

                        if (!varlink_idl_interface_name_is_valid(de->d_name)) {
                                log_debug("Found file '%s' whose names does not qualify as valid Varlink interface name, skipping.", de->d_name);
                                continue;
                        }

                        _cleanup_free_ char *j = path_join(reg_path, de->d_name);
                        if (!j)
                                return log_oom();

                        switch (de->d_type) {
                        case DT_LNK: {
                                _cleanup_free_ char *resolved = NULL;

                                r = chase(j, /* root= */ NULL, CHASE_MUST_BE_SOCKET, &resolved, /* ret_fd= */ NULL);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to resolve '%s', skipping: %m", j);
                                        continue;
                                }

                                _cleanup_free_ char *address = strjoin("unix:", resolved);
                                if (!address)
                                        return log_oom();

                                r = table_add_many(
                                                table,
                                                TABLE_STRING, de->d_name,
                                                TABLE_STRING, address);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        case DT_SOCK: {
                                _cleanup_free_ char *address = strjoin("unix:", j);
                                if (!address)
                                        return log_oom();

                                r = table_add_many(
                                                table,
                                                TABLE_STRING, de->d_name,
                                                TABLE_STRING, address);
                                if (r < 0)
                                        return r;

                                break;
                        }

                        default:
                                log_debug("Ignoring inode '%s' of unexpected type: %m", de->d_name);
                        }
                }
        }

        if (!table_isempty(table) || sd_json_format_enabled(arg_json_format_flags)) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }

        if (arg_legend && !sd_json_format_enabled(arg_json_format_flags)) {
                if (table_isempty(table))
                        printf("No services registered.\n");
                else
                        printf("\n%zu registered services listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int varlinkctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "info",            2,        2,        0, verb_info          },
                { "list-interfaces", 2,        2,        0, verb_info          },
                { "introspect",      2,        VERB_ANY, 0, verb_introspect    },
                { "list-methods",    2,        VERB_ANY, 0, verb_introspect    },
                { "call",            3,        VERB_ANY, 0, verb_call          },
                { "list-registry",   VERB_ANY, 1,        0, verb_list_registry },
                { "validate-idl",    1,        2,        0, verb_validate_idl  },
                { "help",            VERB_ANY, VERB_ANY, 0, verb_help          },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return varlinkctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
