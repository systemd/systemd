/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <sys/stat.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-polkit.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "fs-util.h"
#include "hashmap.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "path-lookup.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "runtime-scope.h"
#include "stat-util.h"
#include "storage-util.h"
#include "string-table.h"
#include "uid-classification.h"
#include "varlink-io.systemd.StorageProvider.h"
#include "varlink-util.h"

static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;

/* For now we maintain a simple, compiled-in list of templates. One of those days we might want to move these
 * into configurable drop-in files on disk. */
typedef enum Template {
        TEMPLATE_SPARSE_FILE,
        TEMPLATE_ALLOCATED_FILE,
        TEMPLATE_DIRECTORY,
        TEMPLATE_SUBVOLUME,
        _TEMPLATE_MAX,
        _TEMPLATE_INVALID = -EINVAL,
} Template;

static const char *template_table[_TEMPLATE_MAX] = {
        [TEMPLATE_SPARSE_FILE]    = "sparse-file",
        [TEMPLATE_ALLOCATED_FILE] = "allocated-file",
        [TEMPLATE_DIRECTORY]      = "directory",
        [TEMPLATE_SUBVOLUME]      = "subvolume",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(template, Template);

static VolumeType volume_type_from_template(Template t) {
        switch (t) {

        case TEMPLATE_SPARSE_FILE:
        case TEMPLATE_ALLOCATED_FILE:
                return VOLUME_REG;

        case TEMPLATE_DIRECTORY:
        case TEMPLATE_SUBVOLUME:
                return VOLUME_DIR;

        default:
                return _VOLUME_TYPE_INVALID;
        }
}

static int open_storage_dir(void) {
        int r;

        _cleanup_free_ char *state_dir = NULL;
        r = state_directory_generic(arg_runtime_scope, /* suffix= */ NULL, &state_dir);
        if (r < 0)
                return log_error_errno(r, "Failed to get state directory path: %m");

        _cleanup_close_ int state_fd = chase_and_open(state_dir, /* root= */ NULL, CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        if (state_fd < 0)
                return log_error_errno(state_fd, "Failed to open '%s': %m", state_dir);

        /* First we try to open the storage directory. If it exists this will work and we are happy. If we
         * get ENOENT we'll try to create it. If that works, great. If we get EEXIST we'll try to reopen it
         * again, to deal with other instances of ourselves racing with us. We only do this exactly once
         * though, under the assumption that the dir is never removed, only created during runtime. */
        _cleanup_close_ int storage_fd = chase_and_openat(XAT_FDROOT, state_fd, "storage", CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        if (storage_fd == -ENOENT) {
                storage_fd = xopenat_full(state_fd, "storage", O_EXCL|O_CREAT|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW, XO_LABEL|XO_SUBVOLUME, 0700);
                if (storage_fd == -EEXIST)
                        storage_fd = chase_and_openat(XAT_FDROOT, state_fd, "storage", CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        }
        if (storage_fd < 0)
                return log_error_errno(storage_fd, "Failed to open '%s/storage/': %m", state_dir);

        return TAKE_FD(storage_fd);
}

static int vl_method_list_volumes(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        struct {
                const char *match_name;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "matchName", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, match_name), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_close_ int fd = open_storage_dir();
        if (fd < 0)
                return fd;

        _cleanup_free_ DirectoryEntries *dentries = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT, &dentries);
        if (r < 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.StorageProvider.NoSuchVolume");
        if (r < 0)
                return r;

        FOREACH_ARRAY(dp, dentries->entries, dentries->n_entries) {
                struct dirent *d = *dp;

                if (!IN_SET(d->d_type, DT_REG, DT_DIR, DT_UNKNOWN))
                        continue;

                const char *a = startswith(d->d_name, "_");
                if (!a)
                        continue;

                const char *e = endswith(a, ".volume");
                if (!e)
                        continue;

                _cleanup_free_ char *n = strndup(a, e - a);
                if (!n)
                        return log_oom_debug();

                if (!volume_name_is_valid(n))
                        continue;

                if (p.match_name && fnmatch(p.match_name, n, /* flags= */ 0) != 0)
                        continue;

                struct stat st;
                if (fstatat(fd, d->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;
                        return log_debug_errno(errno, "Failed to stat() '%s' in storage directory: %m", d->d_name);
                }

                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", n),
                                SD_JSON_BUILD_PAIR_STRING("type", inode_type_to_string(st.st_mode)),
                                SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", false),
                                SD_JSON_BUILD_PAIR_CONDITION(S_ISREG(st.st_mode), "sizeBytes", SD_JSON_BUILD_UNSIGNED(st.st_size)),
                                SD_JSON_BUILD_PAIR_CONDITION(S_ISREG(st.st_mode), "usedBytes", SD_JSON_BUILD_UNSIGNED((uint64_t) st.st_blocks * 512U)));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_list_templates(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        struct {
                const char *match_name;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "matchName", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, match_name), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.StorageProvider.NoSuchTemplate");
        if (r < 0)
                return r;

        for (Template t = 0; t < _TEMPLATE_MAX; t++) {
                const char *n = template_to_string(t);

                if (p.match_name && fnmatch(p.match_name, n, FNM_PATHNAME) != 0)
                        continue;

                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", n),
                                SD_JSON_BUILD_PAIR_STRING("type", volume_type_to_string(volume_type_from_template(t))));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int create_volume_dir(
                int storage_fd,
                const char *filename,
                Template t) {

        int r;

        assert(storage_fd >= 0);
        assert(filename);

        XOpenFlags xopen_flags;
        switch (t) {

        case TEMPLATE_DIRECTORY:
                xopen_flags = 0;
                break;

        case TEMPLATE_SUBVOLUME:
                xopen_flags = XO_SUBVOLUME;
                break;

        default:
                return -ENOMEDIUM; /* Recognizable error for: template doesn't apply here */
        }

        _cleanup_close_ int fd = xopenat_full(storage_fd, filename, O_CREAT|O_EXCL|O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, xopen_flags, 0755);
        if (fd < 0)
                return fd;

        r = RET_NERRNO(fchown(fd, FOREIGN_UID_MIN, FOREIGN_UID_MIN));
        if (r < 0) {
                (void) unlinkat(storage_fd, filename, AT_REMOVEDIR);
                return r;
        }

        return TAKE_FD(fd);
}

static int create_volume_reg(
                int storage_fd,
                const char *filename,
                Template t,
                uint64_t create_size) {
        int r;

        assert(storage_fd >= 0);
        assert(filename);

        bool sparse;
        switch (t) {

        case TEMPLATE_SPARSE_FILE:
                sparse = true;
                break;

        case TEMPLATE_ALLOCATED_FILE:
                sparse = false;
                break;

        default:
                return -ENOMEDIUM; /* Recognizable error for: template doesn't apply here */
        }

        _cleanup_close_ int fd = xopenat_full(storage_fd, filename, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW, XO_NOCOW, 0600);
        if (fd < 0)
                return fd;

        if (sparse)
                r = RET_NERRNO(ftruncate(fd, create_size));
        else
                r = RET_NERRNO(fallocate(fd, /* mode= */ 0, /* offset= */ 0, create_size));
        if (r < 0) {
                (void) unlinkat(storage_fd, filename, /* flags= */ 0);
                return r;
        }

        return TAKE_FD(fd);
}

static int vl_method_acquire(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        int r;

        assert(link);

        struct {
                const char *name;
                CreateMode create_mode;
                const char *template;
                int read_only;
                VolumeType request_as;
                uint64_t create_size;
        } p = {
                .create_mode = CREATE_ANY,
                .read_only = -1,
                .request_as = _VOLUME_TYPE_INVALID,
                .create_size = UINT64_MAX,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",       SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, name),        SD_JSON_MANDATORY },
                { "createMode", SD_JSON_VARIANT_STRING,        json_dispatch_create_mode,     voffsetof(p, create_mode), 0                 },
                { "template",   SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, template),    0                 },
                { "readOnly",   SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     voffsetof(p, read_only),   0                 },
                { "requestAs",  SD_JSON_VARIANT_STRING,        json_dispatch_volume_type,     voffsetof(p, request_as),  0                 },
                { "createSize", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, create_size), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!string_is_safe(p.name, /* flags= */ 0))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (!IN_SET(p.create_mode, CREATE_ANY, CREATE_OPEN, CREATE_NEW))
                return sd_varlink_error(link, "io.systemd.StorageProvider.CreateNotSupported", NULL);

        if (p.request_as >= 0 && !IN_SET(p.request_as, VOLUME_REG, VOLUME_DIR))
                return sd_varlink_error(link, "io.systemd.StorageProvider.InvalidRequestAs", NULL);

        Template t = _TEMPLATE_INVALID;
        if (!isempty(p.template)) {
                t = template_from_string(p.template);
                if (t < 0)
                        return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchTemplate", NULL);
        }

        if (p.read_only > 0) {
                if (p.create_mode == CREATE_NEW)
                        return sd_varlink_error_invalid_parameter_name(link, "readOnly");

                p.create_mode = CREATE_OPEN;
        }

        /* Add a suffix so that we are never attempted to open a temporary file assuming it was a valid
         * volume. Add a prefix, so that a volume can not be hidden from the administrator. */
        _cleanup_free_ char *filename = strjoin("_", p.name, ".volume");
        if (!filename)
                return log_oom_debug();

        if (!filename_is_valid(filename))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        const char *details[] = {
                "name", p.name,
                NULL
        };

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.storage.fs.acquire",
                        details,
                        polkit_registry);
        if (r <= 0)
                return r;

        _cleanup_close_ int storage_fd = open_storage_dir();
        if (storage_fd < 0)
                return storage_fd;

        _cleanup_close_ int fd = -EBADF;
        bool reopen = false;
        r = chaseat(XAT_FDROOT, storage_fd, filename, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &fd);
        if (r < 0) {
                if (r != -ENOENT || p.create_mode == CREATE_OPEN || p.read_only > 0)
                        return r;

                if (p.request_as < 0) /* Make a choice */
                        p.request_as = VOLUME_DIR;

                /* Try to create the volume */
                switch (p.request_as) {

                case VOLUME_DIR: {

                        if (t < 0)
                                t = TEMPLATE_SUBVOLUME;

                        fd = create_volume_dir(storage_fd, filename, t);
                        if (fd == -EEXIST) /* Exists now? try to open it once more */
                                break;
                        if (fd == -ENOMEDIUM)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.BadTemplate", NULL);
                        if (fd < 0)
                                return fd;

                        // FIXME: use fsopen to create detached mount that is potentially read-only and covers a single mount only
                        break;
                }

                case VOLUME_REG: {
                        if (p.create_size == UINT64_MAX)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.CreateSizeRequired", NULL);

                        if (t < 0)
                                t = TEMPLATE_SPARSE_FILE;

                        fd = create_volume_reg(storage_fd, filename, t, p.create_size);
                        if (fd == -EEXIST)
                                break;
                        if (fd == -ENOMEDIUM)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.BadTemplate", NULL);
                        if (fd < 0)
                                return fd;

                        break;
                }

                default:
                        assert_not_reached();
                }

                if (fd < 0) {
                        /* If we failed to open the volume and reached this point, then the volume already
                         * exists by now (i.e. we ran into the race above). In that case, try to open it */
                        assert(fd == -EEXIST);

                        if (p.create_mode == CREATE_NEW)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.VolumeExists", NULL);

                        r = chaseat(XAT_FDROOT, storage_fd, filename, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &fd);
                        if (r < 0)
                                return r;

                        reopen = true; /* The fd is O_PATH, needs conversion to non-O_PATH */
                }
        } else {
                if (p.create_mode == CREATE_NEW)
                        return sd_varlink_error(link, "io.systemd.StorageProvider.VolumeExists", NULL);

                reopen = true; /* The fd is O_PATH, needs conversion to non-O_PATH */
        }

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;

        if (reopen) {
                XOpenFlags xopen_flags =
                        (p.request_as == VOLUME_DIR ? 0 : XO_REGULAR) |
                        (p.read_only < 0 && !S_ISDIR(st.st_mode) ? XO_AUTO_RW_RO : 0);
                int open_flags =
                        (p.request_as == VOLUME_DIR ? O_DIRECTORY : 0) |
                        (p.read_only < 0 ? 0 : (p.read_only > 0 || S_ISDIR(st.st_mode) ? O_RDONLY : O_RDWR));

                _cleanup_close_ int reopened_fd = xopenat_full(fd, /* path= */ NULL, open_flags|O_CLOEXEC, xopen_flags, /* mode= */ MODE_INVALID);
                if (reopened_fd < 0)
                        return log_debug_errno(reopened_fd, "Failed to reopen volume fd for '%s': %m", filename);

                close_and_replace(fd, reopened_fd);
        }

        int open_flags = fcntl(fd, F_GETFL, 0);
        if (open_flags < 0)
                return -errno;

        int idx = sd_varlink_push_fd(link, fd);
        if (idx < 0)
                return idx;

        TAKE_FD(fd);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("fileDescriptorIndex", idx),
                        SD_JSON_BUILD_PAIR_STRING("volumeType", inode_type_to_string(st.st_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", (open_flags & O_ACCMODE_STRICT) == O_RDONLY));
}

static int vl_server(void) {
        int r;

        _cleanup_(hashmap_freep) Hashmap *polkit_registry = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_HANDLE_SIGINT|
                        SD_VARLINK_SERVER_HANDLE_SIGTERM|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        &polkit_registry);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_StorageProvider);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.StorageProvider.Acquire", vl_method_acquire,
                        "io.systemd.StorageProvider.ListVolumes", vl_method_list_volumes,
                        "io.systemd.StorageProvider.ListTemplates", vl_method_list_templates);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int help(void) {
        int r;

        help_cmdline("[OPTIONS...]");
        help_abstract("Simple file system backed storage volume service");

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_section("Options:");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-storage-fs", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
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

                OPTION_LONG("system", NULL, "Operate in system mode"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Operate in user mode"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                }

        if (option_parser_get_n_args(&state) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        return 1;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
