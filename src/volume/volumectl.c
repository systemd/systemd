/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "argv-util.h"
#include "build.h"
#include "errno-list.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-table.h"
#include "json-util.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "recurse-dir.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-util.h"
#include "verbs.h"
#include "volume-util.h"

static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;

static int help(void) {
        int r;

        _cleanup_free_ char *link = NULL;
        r = terminal_urlify_man("volumectl", "1", &link);
        if (r < 0)
                return log_oom();

        _cleanup_(table_unrefp) Table *verbs = NULL;
        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] COMMAND\n"
               "\n%sEnumerate volumes and services%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static const char *ro_color(int ro) {
        if (ro > 0)
                return ansi_highlight_red();
        if (ro == 0)
                return ansi_highlight_green();

        return NULL;
}

static int on_list_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void* userdata) {

        Table *t = ASSERT_PTR(userdata);
        int r;

        assert(link);

        const char *d = ASSERT_PTR(sd_varlink_get_description(link));

        if (error_id) {
                log_debug("%s: Received error '%s', ignoring.", d, error_id);
                return 0;
        }

        _cleanup_free_ char *service = NULL;
        r = path_extract_filename(d, &service);
        if (r < 0)
                return log_error_errno(r, "Failed to extract service name from socket path: %m");

        struct {
                const char *name;
                const char *type;
                int read_only;
                uint64_t size_bytes;
                uint64_t used_bytes;
        } p = {
                .read_only = -1,
                .size_bytes = UINT64_MAX,
                .used_bytes = UINT64_MAX,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, name),       0 },
                { "type",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, type),       0 },
                { "readOnly",  SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     voffsetof(p, read_only),  0 },
                { "sizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, size_bytes), 0 },
                { "usedBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, used_bytes), 0 },
                {}
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to decode List() reply: %m");

        r = table_add_many(
                        t,
                        TABLE_STRING, service,
                        TABLE_STRING, p.name,
                        TABLE_STRING, p.type,
                        TABLE_TRISTATE, p.read_only,
                        TABLE_SET_COLOR, ro_color(p.read_only));
        if (r < 0)
                return table_log_add_error(r);

        if (p.size_bytes == UINT64_MAX)
                r = table_add_many(t, TABLE_EMPTY, TABLE_SET_ALIGN_PERCENT, 100);
        else
                r = table_add_many(t, TABLE_SIZE, p.size_bytes, TABLE_SET_ALIGN_PERCENT, 100);
        if (r < 0)
                return table_log_add_error(r);

        if (p.used_bytes == UINT64_MAX)
                r = table_add_many(t, TABLE_EMPTY, TABLE_SET_ALIGN_PERCENT, 100);
        else
                r = table_add_many(t, TABLE_SIZE, p.used_bytes, TABLE_SET_ALIGN_PERCENT, 100);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int verb_list(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc <= 2);

        _cleanup_(table_unrefp) Table *t = table_new("service", "name", "type", "ro", "size", "used");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0, (size_t) 1);
        (void) table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (argc >= 2) {
                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("matchName", argv[1]));
                if (r < 0)
                        return log_oom();
        }

        r = varlink_execute_directory(
                        "/run/systemd/storage/",
                        "io.systemd.Volumes.List",
                        v,
                        /* more= */ true,
                        on_list_reply,
                        t);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to enumerate volumes: %m");

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF)) {
                if (table_isempty(t))
                        printf("No volumes.\n");
                else
                        printf("\n%zu volumes listed.\n", table_get_rows(t) - 1);
        }

        return 0;
}

VERB(verb_list, "list", "GLOB", /* min_args= */ VERB_ANY, /* max_args= */ 2, /* flags= */ 0, "List volumes");

static int on_list_templates_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void* userdata) {

        Table *t = ASSERT_PTR(userdata);
        int r;

        assert(link);

        const char *d = ASSERT_PTR(sd_varlink_get_description(link));

        if (error_id) {
                log_debug("%s: Received error '%s', ignoring.", d, error_id);
                return 0;
        }

        _cleanup_free_ char *service = NULL;
        r = path_extract_filename(d, &service);
        if (r < 0)
                return log_error_errno(r, "Failed to extract service name from socket path: %m");

        struct {
                const char *name;
                const char *type;
        } p = {
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, name), 0 },
                { "type", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, type), 0 },
                {}
        };

        r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to decode ListTemplates() reply: %m");

        r = table_add_many(
                        t,
                        TABLE_STRING, service,
                        TABLE_STRING, p.name,
                        TABLE_STRING, p.type);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int verb_templates(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc <= 2);

        _cleanup_(table_unrefp) Table *t = table_new("service", "name", "type");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0, (size_t) 1);
        (void) table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (argc >= 2) {
                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("matchName", argv[1]));
                if (r < 0)
                        return log_oom();
        }

        r = varlink_execute_directory(
                        "/run/systemd/storage/",
                        "io.systemd.Volumes.ListTemplates",
                        v,
                        /* more= */ true,
                        on_list_templates_reply,
                        t);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to enumerate volume templates: %m");

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF)) {
                if (table_isempty(t))
                        printf("No templates.\n");
                else
                        printf("\n%zu templates listed.\n", table_get_rows(t) - 1);
        }

        return 0;
}

VERB(verb_templates, "templates", "GLOB", /* min_args= */ VERB_ANY, /* max_args= */ 2, /* flags= */ 0, "List volume templates");

static int verb_services(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        _cleanup_(table_unrefp) Table *t = table_new("service", "listening");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0);

        _cleanup_close_ int fd = open("/run/systemd/storage/", O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open /run/systemd/storage/: %m");
        } else {
                _cleanup_free_ DirectoryEntries *dentries = NULL;
                r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &dentries);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate /run/systemd/storage/: %m");

                FOREACH_ARRAY(dp, dentries->entries, dentries->n_entries) {
                        struct dirent *de = *dp;

                        _cleanup_close_ int socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        if (socket_fd < 0)
                                return log_error_errno(errno, "Failed to allocate AF_UNIX/SOCK_STREAM socket: %m");

                        _cleanup_free_ char *no = NULL;
                        r = connect_unix_path(socket_fd, fd, de->d_name);
                        if (r < 0) {
                                no = strjoin("No (", ERRNO_NAME(r), ")");
                                if (!no)
                                        return log_oom();
                        }

                        r = table_add_many(t,
                                           TABLE_STRING, de->d_name,
                                           TABLE_STRING, no ?: "yes",
                                           TABLE_SET_COLOR, ansi_highlight_green_red(!no));
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF)) {
                if (table_isempty(t))
                        printf("No services.\n");
                else
                        printf("\n%zu services listed.\n", table_get_rows(t) - 1);
        }

        return 0;
}

VERB_NOARG(verb_services, "services", "List volume services");

static int parse_argv(int argc, char *argv[], char ***args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;
        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;
                }

        *args = option_parser_get_args(&state);
        return 1;
}

static int run_as_mount_helper(int argc, char *argv[]) {
        int c, r;

        /* Implements util-linux "external helper" command line interface, as per mount(8) man page.
         *
         * Usage:
         *
         *  mount -t volume fs:dirvolume /some/place          # Directory volumes
         *  mount -t volume.ext4 fs:blkvolume /some/place     # Block volumes
         */

        const char *fstype = NULL, *options = NULL;
        bool fake = false;

        while ((c = getopt(argc, argv, "sfnvN:o:t:")) >= 0) {
                switch (c) {

                case 'f':
                        fake = true;
                        break;

                case 'o':
                        options = optarg;
                        break;

                case 't':
                        fstype = startswith(optarg, "volume.");
                        if (fstype) {
                                /* Paranoia: don't allow "volume.volume.volume.…" chains... */
                                if (startswith(fstype, "volume.") || streq(fstype, "volume"))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Refusing nested volumes.");
                        } else if (!streq(optarg, "volume"))
                                log_debug("Unexpected file system type '%s', ignoring.", optarg);

                        break;

                case 's': /* sloppy mount options */
                case 'n': /* aka --no-mtab */
                case 'v': /* aka --verbose */
                        log_debug("Ignoring option -%c, not implemented.", c);
                        break;

                case 'N': /* aka --namespace= */
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Option -%c is not implemented, refusing.", c);

                case '?':
                        return -EINVAL;
                }
        }

        if (optind + 2 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected an image file path and target directory as only argument.");

        const char *colon = strchr(argv[optind], ':');
        if (!colon)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid volume specification, refusing: %s", argv[optind]);

        _cleanup_free_ char *service = strndup(argv[optind], colon - argv[optind]);
        if (!service)
                return log_oom();
        if (!service_name_is_valid(service))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid service name: %s", service);

        _cleanup_free_ char *name = strdup(colon + 1);
        if (!name)
                return log_oom();
        if (!volume_name_is_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid volume name: %s", name);

        _cleanup_free_ char *path = NULL;
        r = parse_path_argument(argv[optind+1], /* suppress_root= */ false, &path);
        if (r < 0)
                return r;

        _cleanup_free_ char *filtered = NULL, *template = NULL;
        CreateMode create_mode = _CREATE_MODE_INVALID;
        uint64_t create_size = UINT64_MAX;
        int read_only = -1;
        for (const char *p = options;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", EXTRACT_KEEP_QUOTE);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract mount option: %m");
                if (r == 0)
                        break;

                const char *t = startswith(word, "volume.");
                if (t) {
                        const char *v;
                        if ((v = startswith(t, "create="))) {
                                create_mode = create_mode_from_string(v);
                                if (create_mode < 0)
                                        return log_error_errno(create_mode, "Failed to parse volume.create= parameter: %s", v);
                        } else if ((v = startswith(t, "create-size="))) {
                                r = parse_size(v, /* base= */ 1024, &create_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse volume.create-size= parameter: %s", v);
                        } else if ((v = startswith(t, "template="))) {
                                if (!template_name_is_valid(v))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid template name, refusing: %s", v);

                                r = free_and_strdup(&template, v);
                                if (r < 0)
                                        return log_oom();
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown mount option '%s', refusing.", word);
                } else {
                        if (streq(word, "ro"))
                                read_only = true;
                        else if (streq(word, "rw"))
                                read_only = false;

                        if (!strextend_with_separator(&filtered, ",", word))
                                return log_oom();
                }
        }

        if (fake)
                return 0;

        _cleanup_free_ char *socket_path = path_join("/run/systemd/storage", service);
        if (!socket_path)
                return log_oom();

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        r = sd_varlink_connect_address(&link, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to '%s': %m", socket_path);

        r = sd_varlink_set_allow_fd_passing_input(link, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable file descriptor passing: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        r = varlink_callbo_and_log(
                        link,
                        "io.systemd.Volumes.Acquire",
                        &reply,
                        SD_JSON_BUILD_PAIR_STRING("name", name),
                        SD_JSON_BUILD_PAIR_CONDITION(create_mode >= 0, "createMode", SD_JSON_BUILD_STRING(create_mode_to_string(create_mode))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("template", template),
                        SD_JSON_BUILD_PAIR_CONDITION(read_only >= 0, "readOnly", SD_JSON_BUILD_BOOLEAN(read_only)),
                        SD_JSON_BUILD_PAIR_CONDITION(create_size != UINT64_MAX, "createSize", SD_JSON_BUILD_UNSIGNED(create_size)));
        if (r < 0)
                return r;

        struct {
                unsigned fd_idx;
                int read_only;
        } p = {
                .fd_idx = UINT_MAX,
                .read_only = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "fileDescriptorIndex", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,     voffsetof(p, fd_idx),     0 },
                { "readOnly",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, voffsetof(p, read_only),  0 },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to decode List() reply: %m");

        _cleanup_close_ int fd = sd_varlink_take_fd(link, p.fd_idx);
        if (fd < 0)
                return log_error_errno(fd, "Failed to acquire fd from Varlink connection: %m");

        _cleanup_strv_free_ char **cmdline = strv_new("mount");
        if (!cmdline)
                return log_oom();

        if (fstype) {
                if (strv_extend_strv(&cmdline, STRV_MAKE("-t", fstype), /* filter_duplicates= */ false) < 0)
                        return log_oom();
        } else if (strv_extend(&cmdline, "--bind") < 0)
                return log_oom();

        if (filtered && strv_extend_strv(&cmdline, STRV_MAKE("-o", filtered), /* filter_duplicates= */ false) < 0)
                return log_oom();

        r = strv_extend_strv(&cmdline, STRV_MAKE(FORMAT_PROC_FD_PATH(fd), path), /* filter_duplicates= */ false);
        if (r < 0)
                return r;

        r = fd_cloexec(fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for mount fd: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *q = quote_command_line(cmdline, SHELL_ESCAPE_EMPTY);
                log_debug("Chain-loading: %s", strna(q));
        }

        execvp("mount", cmdline);
        return log_error_errno(errno, "Failed to execute mount tool: %m");
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        if (invoked_as(argv, "mount.volume"))
                return run_as_mount_helper(argc, argv);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb_with_args(args, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);
