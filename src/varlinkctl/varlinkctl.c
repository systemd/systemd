/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "build.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "terminal-util.h"
#include "varlink.h"
#include "verbs.h"
#include "version.h"

static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static VarlinkMethodFlags arg_method_flags = 0;

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
               "  introspect ADDRESS INTERFACE\n"
               "                         Show interface definition\n"
               "  call ADDRESS METHOD [PARAMS]\n"
               "                         Invoke method\n"
               "  validate-idl [FILE]    Validate interface description\n"
               "  help                   Show this help\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --more              Request multiple responses\n"
               "     --oneway            Do not request response\n"
               "     --json=MODE         Output as JSON\n"
               "  -j                     Same as --json=pretty on tty, --json=short otherwise\n"
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
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'          },
                { "version",  no_argument,       NULL, ARG_VERSION  },
                { "no-pager", no_argument,       NULL, ARG_NO_PAGER },
                { "more",     no_argument,       NULL, ARG_MORE     },
                { "oneway",   no_argument,       NULL, ARG_ONEWAY   },
                { "json",     required_argument, NULL, ARG_JSON     },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hj", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_MORE:
                        arg_method_flags = (arg_method_flags & ~VARLINK_METHOD_ONEWAY) | VARLINK_METHOD_MORE;
                        break;

                case ARG_ONEWAY:
                        arg_method_flags = (arg_method_flags & ~VARLINK_METHOD_MORE) | VARLINK_METHOD_ONEWAY;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case 'j':
                        arg_json_format_flags = JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* If more than one reply is expected, imply JSON-SEQ output */
        if (FLAGS_SET(arg_method_flags, VARLINK_METHOD_MORE))
                arg_json_format_flags |= JSON_FORMAT_SEQ;

        return 1;
}

static int varlink_connect_auto(Varlink **ret, const char *where) {
        int r;

        assert(ret);
        assert(where);

        if (STARTSWITH_SET(where, "/", "./")) { /* If the string starts with a slash or dot slash we use it as a file system path */
                _cleanup_close_ int fd = -EBADF;
                struct stat st;

                fd = open(where, O_PATH|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", where);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", where);

                /* Is this a socket in the fs? Then connect() to it. */
                if (S_ISSOCK(st.st_mode)) {
                        r = varlink_connect_address(ret, FORMAT_PROC_FD_PATH(fd));
                        if (r < 0)
                                return log_error_errno(r, "Failed to connect to '%s': %m", where);

                        return 0;
                }

                /* Is this an executable binary? Then fork it off. */
                if (S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
                        r = varlink_connect_exec(ret, where, STRV_MAKE(where)); /* Ideally we'd use FORMAT_PROC_FD_PATH(fd) here too, but that breaks the #! logic */
                        if (r < 0)
                                return log_error_errno(r, "Failed to spawn '%s' process: %m", where);

                        return 0;
                }

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unrecognized path '%s' is neither an AF_UNIX socket, nor an executable binary.", where);
        }

        /* Otherwise assume this is an URL */
        r = varlink_connect_url(ret, where);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to URL '%s': %m", where);

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
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        const char *url;
        int r;

        assert(argc == 2);
        url = argv[1];

        r = varlink_connect_auto(&vl, url);
        if (r < 0)
                return r;

        JsonVariant *reply = NULL;
        const char *error = NULL;
        r = varlink_call(vl, "org.varlink.service.GetInfo", NULL, &reply, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue GetInfo() call: %m");
        if (error)
                return log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call GetInfo() failed: %s", error);

        pager_open(arg_pager_flags);

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {
                static const struct JsonDispatch dispatch_table[] = {
                        { "vendor",     JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(GetInfoData, vendor),     JSON_MANDATORY },
                        { "product",    JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(GetInfoData, product),    JSON_MANDATORY },
                        { "version",    JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(GetInfoData, version),    JSON_MANDATORY },
                        { "url",        JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(GetInfoData, url),        JSON_MANDATORY },
                        { "interfaces", JSON_VARIANT_ARRAY,  json_dispatch_strv,         offsetof(GetInfoData, interfaces), JSON_MANDATORY },
                        {}
                };
                _cleanup_(get_info_data_done) GetInfoData data = {};

                r = json_dispatch(reply, dispatch_table, JSON_LOG, &data);
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
                JsonVariant *v;

                v = streq_ptr(argv[0], "list-interfaces") ?
                        json_variant_by_key(reply, "interfaces") : reply;

                json_variant_dump(v, arg_json_format_flags, stdout, NULL);
        }

        return 0;
}

typedef struct GetInterfaceDescriptionData {
        const char *description;
} GetInterfaceDescriptionData;

static int verb_introspect(int argc, char *argv[], void *userdata) {
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        const char *url, *interface;
        int r;

        assert(argc == 3);
        url = argv[1];
        interface = argv[2];

        r = varlink_connect_auto(&vl, url);
        if (r < 0)
                return r;

        JsonVariant *reply = NULL;
        const char *error = NULL;
        r = varlink_callb(vl, "org.varlink.service.GetInterfaceDescription", &reply, &error, NULL, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_STRING("interface", interface)));
        if (r < 0)
                return log_error_errno(r, "Failed to issue GetInterfaceDescription() call: %m");
        if (error)
                return log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call GetInterfaceDescription() failed: %s", error);

        pager_open(arg_pager_flags);

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {
                static const struct JsonDispatch dispatch_table[] = {
                        { "description",  JSON_VARIANT_STRING, json_dispatch_const_string, 0, JSON_MANDATORY },
                        {}
                };
                _cleanup_(varlink_interface_freep) VarlinkInterface *vi = NULL;
                const char *description = NULL;
                unsigned line = 0, column = 0;

                r = json_dispatch(reply, dispatch_table, JSON_LOG, &description);
                if (r < 0)
                        return r;

                /* Try to parse the returned description, so that we can add syntax highlighting */
                r = varlink_idl_parse(ASSERT_PTR(description), &line, &column, &vi);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse returned interface description at %u:%u, showing raw interface description: %m", line, column);

                        fputs(description, stdout);
                        if (!endswith(description, "\n"))
                                fputs("\n", stdout);
                } else {
                        r = varlink_idl_dump(stdout, /* use_colors= */ -1, vi);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format parsed interface description: %m");
                }
        } else
                json_variant_dump(reply, arg_json_format_flags, stdout, NULL);

        return 0;
}

static int reply_callback(
                Varlink *link,
                JsonVariant *parameters,
                const char *error,
                VarlinkReplyFlags flags,
                void *userdata)  {

        int r;

        assert(link);

        if (error) {
                /* Propagate the error we received via sd_notify() */
                (void) sd_notifyf(/* unset_environment= */ false, "VARLINKERROR=%s", error);

                r = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call failed: %s", error);
        } else
                r = 0;

        json_variant_dump(parameters, arg_json_format_flags, stdout, NULL);
        return r;
}

static int verb_call(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *jp = NULL;
        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        const char *url, *method, *parameter;
        unsigned line = 0, column = 0;
        int r;

        assert(argc >= 3);
        assert(argc <= 4);
        url = argv[1];
        method = argv[2];
        parameter = argc > 3 && !streq(argv[3], "-") ? argv[3] : NULL;

        arg_json_format_flags &= ~JSON_FORMAT_OFF;

        if (parameter) {
                /* <argv[4]> is correct, as dispatch_verb() shifts arguments by one for the verb. */
                r = json_parse_with_source(parameter, "<argv[4]>", 0, &jp, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse parameters at <argv[4]>:%u:%u: %m", line, column);
        } else {
                r = json_parse_file_at(stdin, AT_FDCWD, "<stdin>", 0, &jp, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse parameters at <stdin>:%u:%u: %m", line, column);
        }

        r = varlink_connect_auto(&vl, url);
        if (r < 0)
                return r;

        if (arg_method_flags & VARLINK_METHOD_ONEWAY) {
                r = varlink_send(vl, method, jp);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);

                r = varlink_flush(vl);
                if (r < 0)
                        return log_error_errno(r, "Failed to flush Varlink connection: %m");

        } else if (arg_method_flags & VARLINK_METHOD_MORE) {

                varlink_set_userdata(vl, (void*) method);

                r = varlink_bind_reply(vl, reply_callback);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind reply callback: %m");

                r = varlink_observe(vl, method, jp);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);

                for (;;) {
                        r = varlink_is_idle(vl);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check if varlink connection is idle: %m");
                        if (r > 0)
                                break;

                        r = varlink_process(vl);
                        if (r < 0)
                                return log_error_errno(r, "Failed to process varlink connection: %m");
                        if (r != 0)
                                continue;

                        r = varlink_wait(vl, USEC_INFINITY);
                        if (r < 0)
                                return log_error_errno(r, "Failed to wait for varlink connection events: %m");
                }
        } else {
                JsonVariant *reply = NULL;
                const char *error = NULL;

                r = varlink_call(vl, method, jp, &reply, &error, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to issue %s() call: %m", method);

                /* If the server returned an error to us, then fail, but first output the associated parameters */
                if (error) {
                        /* Propagate the error we received via sd_notify() */
                        (void) sd_notifyf(/* unset_environment= */ false, "VARLINKERROR=%s", error);

                        r = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call %s() failed: %s", method, error);
                } else
                        r = 0;

                pager_open(arg_pager_flags);

                json_variant_dump(reply, arg_json_format_flags, stdout, NULL);
                return r;
        }

        return 0;
}

static int verb_validate_idl(int argc, char *argv[], void *userdata) {
        _cleanup_(varlink_interface_freep) VarlinkInterface *vi = NULL;
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

        r = varlink_idl_parse(text, &line, &column, &vi);
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

        pager_open(arg_pager_flags);

        r = varlink_idl_dump(stdout, /* use_colors= */ -1, vi);
        if (r < 0)
                return log_error_errno(r, "Failed to format parsed interface description: %m");

        return 0;
}

static int varlinkctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "info",            2,        2,        0, verb_info         },
                { "list-interfaces", 2,        2,        0, verb_info         },
                { "introspect",      3,        3,        0, verb_introspect   },
                { "call",            3,        4,        0, verb_call         },
                { "validate-idl",    1,        2,        0, verb_validate_idl },
                { "help",            VERB_ANY, VERB_ANY, 0, verb_help         },
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
