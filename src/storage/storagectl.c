/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "argv-util.h"
#include "build.h"
#include "bus-util.h"
#include "errno-list.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "help-util.h"
#include "machine-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "polkit-agent.h"
#include "recurse-dir.h"
#include "runtime-scope.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "storage-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "varlink-util.h"
#include "verbs.h"

static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_ask_password = true;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

static int help(void) {
        int r;

        help_cmdline("[OPTIONS...] COMMAND");
        help_abstract("Enumerate storage volumes and providers.");

        _cleanup_(table_unrefp) Table *verbs = NULL;
        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table_ns("storagectl", &options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        help_section("Commands");

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("storagectl", "1");
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

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

        _cleanup_free_ char *provider = NULL;
        r = path_extract_filename(d, &provider);
        if (r < 0)
                return log_error_errno(r, "Failed to extract provider name from socket path: %m");

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
                        TABLE_STRING, provider,
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

VERB(verb_list_volumes, "volumes", "GLOB", /* min_args= */ VERB_ANY, /* max_args= */ 2, VERB_DEFAULT, "List storage volumes");
static int verb_list_volumes(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc <= 2);

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "systemd/io.systemd.StorageProvider", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine socket directory: %m");

        _cleanup_(table_unrefp) Table *t = table_new("provider", "name", "type", "ro", "size", "used");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0, (size_t) 1);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (argc >= 2) {
                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("matchName", argv[1]));
                if (r < 0)
                        return log_oom();
        }

        ssize_t n = varlink_execute_directory(
                        socket_path,
                        "io.systemd.StorageProvider.ListVolumes",
                        v,
                        /* more= */ true,
                        /* timeout_usec= */ 0, /* 0 means default */
                        on_list_reply,
                        t);
        if (n < 0 && n != -ENOENT)
                return log_error_errno(n, "Failed to enumerate storage volumes: %m");

        if (!table_isempty(t)) {
                r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;
        }

        if (arg_legend && FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF)) {
                if (table_isempty(t))
                        printf("No storage volumes.\n");
                else
                        printf("\n%zu storage volumes listed.\n", table_get_rows(t) - 1);
        }

        return 0;
}

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

        _cleanup_free_ char *provider = NULL;
        r = path_extract_filename(d, &provider);
        if (r < 0)
                return log_error_errno(r, "Failed to extract provider name from socket path: %m");

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
                        TABLE_STRING, provider,
                        TABLE_STRING, p.name,
                        TABLE_STRING, p.type);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

VERB(verb_templates, "templates", "GLOB", /* min_args= */ VERB_ANY, /* max_args= */ 2, /* flags= */ 0, "List storage volume templates");
static int verb_templates(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc <= 2);

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "systemd/io.systemd.StorageProvider", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine socket directory: %m");

        _cleanup_(table_unrefp) Table *t = table_new("provider", "name", "type");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0, (size_t) 1);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        if (argc >= 2) {
                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("matchName", argv[1]));
                if (r < 0)
                        return log_oom();
        }

        ssize_t n = varlink_execute_directory(
                        socket_path,
                        "io.systemd.StorageProvider.ListTemplates",
                        v,
                        /* more= */ true,
                        /* timeout_usec= */ 0, /* 0 means default */
                        on_list_templates_reply,
                        t);
        if (n < 0 && n != -ENOENT)
                return log_error_errno(n, "Failed to enumerate storage volume templates: %m");

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

VERB_NOARG(verb_providers, "providers", "List storage providers");
static int verb_providers(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(arg_runtime_scope, "systemd/io.systemd.StorageProvider", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine socket directory: %m");

        _cleanup_(table_unrefp) Table *t = table_new("provider", "listening");
        if (!t)
                return log_oom();

        (void) table_set_sort(t, (size_t) 0);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        _cleanup_close_ int fd = open(socket_path, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open '%s': %m", socket_path);
        } else {
                _cleanup_free_ DirectoryEntries *dentries = NULL;
                r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE, &dentries);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate '%s': %m", socket_path);

                FOREACH_ARRAY(dp, dentries->entries, dentries->n_entries) {
                        struct dirent *de = *dp;

                        if (de->d_type != DT_SOCK)
                                continue;

                        if (!storage_provider_name_is_valid(de->d_name))
                                continue;

                        _cleanup_close_ int socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                        if (socket_fd < 0)
                                return log_error_errno(errno, "Failed to allocate AF_UNIX/SOCK_STREAM socket: %m");

                        _cleanup_free_ char *no = NULL;
                        r = connect_unix_path(socket_fd, fd, de->d_name);
                        if (r < 0) {
                                no = strjoin("no (", ERRNO_NAME(r), ")");
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
                        printf("No providers.\n");
                else
                        printf("\n%zu providers listed.\n", table_get_rows(t) - 1);
        }

        return 0;
}

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv, .namespace = "storagectl" };
        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("storagectl"): {}

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
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_COMMON_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_COMMON_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                }

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

static int run_as_mount_helper(int argc, char *argv[]) {
        int r;

        /* Implements util-linux "external helper" command line interface, as per mount(8) man page.
         *
         * Usage:
         *
         *  mount -t storage fs:mydirvolume /some/place          # Directory volumes
         *  mount -t storage.ext4 fs:myblkvolume /some/place     # Block volumes
         */

        const char *fstype = NULL, *options = NULL;
        bool fake = false;

        OptionParser opts = { argc, argv, .namespace = "mount.storage" };
        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("mount.storage"): {}

                OPTION_SHORT('f', NULL, /* help= */ NULL):
                        fake = true;
                        break;

                OPTION_SHORT('o', "OPTIONS", /* help= */ NULL):
                        options = opts.arg;
                        break;

                OPTION_SHORT('t', "FSTYPE", /* help= */ NULL):
                        fstype = startswith(opts.arg, "storage.");
                        if (fstype) {
                                /* Paranoia: don't allow "storage.storage.storage.…" chains... */
                                if (startswith(fstype, "storage.") || streq(fstype, "storage"))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Refusing nested storage volumes.");
                        } else if (!streq(opts.arg, "storage"))
                                log_warning("Unexpected file system type '%s', ignoring.", opts.arg);

                        break;

                OPTION_SHORT('s', NULL, /* help= */ NULL): {} /* sloppy mount options */
                OPTION_SHORT('n', NULL, /* help= */ NULL): {} /* aka --no-mtab */
                OPTION_SHORT('v', NULL, /* help= */ NULL):    /* aka --verbose */
                        log_debug("Ignoring option -%c, not implemented.", opts.opt->short_code);
                        break;

                OPTION_SHORT('N', "NS", /* help= */ NULL): /* aka --namespace= */
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Option -%c is not implemented, refusing.",
                                               opts.opt->short_code);
                }

        char **args = option_parser_get_args(&opts);
        size_t n_args = option_parser_get_n_args(&opts);

        if (n_args != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected a storage volume specification and target directory as only arguments.");

        const char *colon = strchr(args[0], ':');
        if (!colon)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid storage volume specification, refusing: %s", args[0]);

        _cleanup_free_ char *provider = strndup(args[0], colon - args[0]);
        if (!provider)
                return log_oom();
        if (!storage_provider_name_is_valid(provider))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid storage provider name: %s", provider);

        _cleanup_free_ char *name = strdup(colon + 1);
        if (!name)
                return log_oom();
        if (!storage_volume_name_is_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid storage volume name: %s", name);

        _cleanup_free_ char *path = NULL;
        r = parse_path_argument(args[1], /* suppress_root= */ false, &path);
        if (r < 0)
                return r;

        _cleanup_free_ char *filtered = NULL, *template = NULL;
        CreateMode create_mode = _CREATE_MODE_INVALID;
        uint64_t create_size = UINT64_MAX;
        ReadOnlyMode read_only = _READ_ONLY_INVALID;
        for (const char *p = options;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", EXTRACT_KEEP_QUOTE|EXTRACT_UNESCAPE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract mount option: %m");
                if (r == 0)
                        break;

                const char *t = startswith(word, "storage.");
                if (t) {
                        const char *v;
                        if ((v = startswith(t, "create="))) {
                                create_mode = create_mode_from_string(v);
                                if (create_mode < 0)
                                        return log_error_errno(create_mode, "Failed to parse storage.create= parameter: %s", v);
                        } else if ((v = startswith(t, "create-size="))) {
                                r = parse_size(v, /* base= */ 1024, &create_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse storage.create-size= parameter: %s", v);
                        } else if ((v = startswith(t, "template="))) {
                                if (!storage_template_name_is_valid(v))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid template name, refusing: %s", v);

                                r = free_and_strdup(&template, v);
                                if (r < 0)
                                        return log_oom();
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown mount option '%s', refusing.", word);
                } else if (streq(word, "ro"))
                        read_only = READ_ONLY_YES;
                else if (streq(word, "rw"))
                        read_only = READ_ONLY_NO;
                else if (!strextend_with_separator(&filtered, ",", word))
                        return log_oom();
        }

        if (fake)
                return 0;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        VolumeType requested_type = fstype ? VOLUME_REG : VOLUME_DIR;

        BindVolume bv = BIND_VOLUME_INIT;
        bv.provider = provider;
        bv.volume = name;
        bv.create_mode = create_mode;
        bv.template = template;
        bv.read_only = read_only;
        bv.request_as = requested_type;
        bv.create_size_bytes = create_size;

        _cleanup_(storage_acquire_reply_done) StorageAcquireReply reply = STORAGE_ACQUIRE_REPLY_INIT;
        _cleanup_free_ char *acquire_error_id = NULL;
        r = storage_acquire_volume(arg_runtime_scope, &bv, arg_ask_password, &acquire_error_id, &reply);
        if (r < 0 && fstype &&
            STR_IN_SET(strna(acquire_error_id),
                       "io.systemd.StorageProvider.TypeNotSupported",
                       "io.systemd.StorageProvider.WrongType")) {
                _cleanup_(storage_acquire_reply_done) StorageAcquireReply retry = STORAGE_ACQUIRE_REPLY_INIT;
                assert(bv.request_as == VOLUME_REG);
                bv.request_as = VOLUME_BLK;
                int k = storage_acquire_volume(arg_runtime_scope, &bv, arg_ask_password, /* reterr_error_id= */ NULL, &retry);
                if (k >= 0) {
                        storage_acquire_reply_done(&reply);
                        reply = retry;
                        retry = STORAGE_ACQUIRE_REPLY_INIT;
                        acquire_error_id = mfree(acquire_error_id);
                        requested_type = VOLUME_BLK;
                        r = 0;
                }
        }

        if (r < 0) {
                const char *eid = acquire_error_id;

                if (streq_ptr(eid, "io.systemd.StorageProvider.NoSuchVolume"))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Volume '%s' not known.", name);
                if (streq_ptr(eid, "io.systemd.StorageProvider.NoSuchTemplate"))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Template '%s' not known.", template);
                if (streq_ptr(eid, "io.systemd.StorageProvider.VolumeExists"))
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Volume '%s' exists already.", name);
                if (streq_ptr(eid, "io.systemd.StorageProvider.TypeNotSupported"))
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Storage provider does not support the specified volume type '%s'.", volume_type_to_string(requested_type));
                if (streq_ptr(eid, "io.systemd.StorageProvider.WrongType"))
                        return log_error_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL), "Volume '%s' is not of type '%s'.", name, volume_type_to_string(requested_type));
                if (streq_ptr(eid, "io.systemd.StorageProvider.CreateNotSupported"))
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Storage provider does not support creating volumes.");
                if (streq_ptr(eid, "io.systemd.StorageProvider.CreateSizeRequired"))
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "Storage provider requires a create size to be provided when creating volumes on-the-fly. Use 'storage.create-size=' mount option.");
                if (streq_ptr(eid, "io.systemd.StorageProvider.ReadOnlyVolume"))
                        return log_error_errno(SYNTHETIC_ERRNO(EROFS), "Volume '%s' is read-only.", name);
                if (streq_ptr(eid, "io.systemd.StorageProvider.BadTemplate"))
                        return log_error_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL), "Template does not apply to this volume type.");

                if (eid)
                        return log_error_errno(r, "Failed to issue io.systemd.StorageProvider.Acquire() varlink call (%s): %m", eid);
                return log_error_errno(r, "Failed to issue io.systemd.StorageProvider.Acquire() varlink call: %m");
        }

        struct stat st;
        if (fstat(reply.fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat returned file descriptor: %m");

        _cleanup_strv_free_ char **cmdline = strv_new("mount", "-c");
        if (!cmdline)
                return log_oom();

        if (fstype) {
                if (!IN_SET(reply.type, VOLUME_REG, VOLUME_BLK))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mounting as file system type '%s' requested, but volume is not a block device or regular file.", fstype);

                r = stat_verify_regular_or_block(&st);
                if (r < 0)
                        return log_error_errno(r, "File descriptor for block/regular volume is not a block or regular inode: %m");

                if (strv_extend_strv(&cmdline, STRV_MAKE("-t", fstype), /* filter_duplicates= */ false) < 0)
                        return log_oom();
        } else {
                if (reply.type != VOLUME_DIR)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mount as directory requested, but volume is not a directory.");

                if (!uid_is_valid(reply.base_uid) || !gid_is_valid(reply.base_gid))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Provider did not report base UID/GID, cannot mount.");

                if (reply.base_uid > UINT32_MAX - USERNS_RANGE_SIZE ||
                    reply.base_gid > UINT32_MAX - USERNS_RANGE_SIZE)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Returned base UID/GID out of range.");

                r = stat_verify_directory(&st);
                if (r < 0)
                        return log_error_errno(r, "File descriptor for directory volume is not a directory inode: %m");

                if (st.st_uid < reply.base_uid || st.st_uid >= reply.base_uid + USERNS_RANGE_SIZE ||
                    st.st_gid < reply.base_gid || st.st_gid >= reply.base_gid + USERNS_RANGE_SIZE)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "File descriptor for directory volume is not owned by base UID/GID range, refusing.");

                /* Now move the mount into our own UID/GID range */
                _cleanup_free_ char *uid_line = asprintf_safe(
                                UID_FMT " " UID_FMT " " UID_FMT "\n",
                                reply.base_uid, (uid_t) 0, USERNS_RANGE_SIZE);
                _cleanup_free_ char *gid_line = asprintf_safe(
                                GID_FMT " " GID_FMT " " GID_FMT "\n",
                                reply.base_gid, (gid_t) 0, USERNS_RANGE_SIZE);
                if (!uid_line || !gid_line)
                        return log_oom();

                _cleanup_close_ int userns_fd = userns_acquire(uid_line, gid_line, /* setgroups_deny= */ true);
                if (userns_fd < 0)
                        return log_error_errno(userns_fd, "Failed to acquire new user namespace: %m");

                _cleanup_close_ int remapped_fd = open_tree_attr_with_fallback(
                                reply.fd,
                                /* path= */ NULL,
                                OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
                                &(struct mount_attr) {
                                          .attr_set = MOUNT_ATTR_IDMAP,
                                          .userns_fd = userns_fd,
                                });
                if (remapped_fd < 0)
                        return log_error_errno(remapped_fd, "Failed to set ID mapping on returned mount: %m");

                close_and_replace(reply.fd, remapped_fd);

                if (strv_extend(&cmdline, "--bind") < 0)
                        return log_oom();
        }

        if (reply.read_only > 0)
                read_only = READ_ONLY_YES;

        if (!strextend_with_separator(&filtered, ",", read_only == READ_ONLY_YES ? "ro" : "rw"))
                return log_oom();

        if (strv_extend_strv(&cmdline, STRV_MAKE("-o", filtered), /* filter_duplicates= */ false) < 0)
                return log_oom();

        if (strv_extend_strv(&cmdline, STRV_MAKE(FORMAT_PROC_FD_PATH(reply.fd), path), /* filter_duplicates= */ false) < 0)
                return log_oom();

        r = fd_cloexec(reply.fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC for mount fd: %m");

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *q = quote_command_line(cmdline, SHELL_ESCAPE_EMPTY);
                log_debug("Chain-loading: %s", strna(q));
        }

        /* NB: we do not honour $PATH here, since as plugin to /bin/mount we might be called in a setuid()
         * context, and hence don't want to chain to programs potentially under user control. */
        execv("/bin/mount", cmdline);
        return log_error_errno(errno, "Failed to execute mount tool: %m");
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        if (invoked_as(argv, "mount.storage"))
                return run_as_mount_helper(argc, argv);

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb_with_args(args, /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);
