/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <sys/stat.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "path-util.h"
#include "stat-util.h"
#include "strv.h"
#include "varlink-io.systemd.Volumes.h"
#include "varlink-util.h"
#include "volume-util.h"
#include "uid-classification.h"
#include "recurse-dir.h"

typedef enum Template {
        TEMPLATE_SPARSE_BLOCK,
        TEMPLATE_ALLOCATED_BLOCK,
        TEMPLATE_PLAIN_DIRECTORY,
        TEMPLATE_BTRFS_SUBVOLUME,
        _TEMPLATE_MAX,
        _TEMPLATE_INVALID = -EBADF,
} Template;

static const char *template_table[_TEMPLATE_MAX] = {
        [TEMPLATE_SPARSE_BLOCK]    = "sparse-block",
        [TEMPLATE_ALLOCATED_BLOCK] = "allocated-block",
        [TEMPLATE_PLAIN_DIRECTORY] = "plain-directory",
        [TEMPLATE_BTRFS_SUBVOLUME] = "btrfs-subvolume",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(template, Template);

static VolumeType volume_type_from_template(Template t) {
        switch (t) {
        case TEMPLATE_SPARSE_BLOCK:
        case TEMPLATE_ALLOCATED_BLOCK:
                return VOLUME_REG;

        case TEMPLATE_PLAIN_DIRECTORY:
        case TEMPLATE_BTRFS_SUBVOLUME:
                return VOLUME_DIR;

        default:
                return _VOLUME_TYPE_INVALID;
        }
}

static bool volume_name_is_valid(const char *n) {
        return string_is_safe(n, /* flags= */ 0);
}

static int open_volumes_dir(void) {
        _cleanup_close_ int var_lib_fd = chase_and_open("/var/lib", /* root= */ NULL, CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        if (var_lib_fd < 0)
                return log_error_errno(var_lib_fd, "Failed to open '/var/lib/': %m");

        /* First we try to open the volumes directory. If it exists this will work and we are happy. If we
         * get ENOENT we'll try to create it. If that works, great. If we get EEXIST we'll try to reopen it
         * again, to deal with other instances of ourselves racing with us. We only do this exactly once
         * though, under the assumption that the dir is never removed, only created during runtime. */
        _cleanup_close_ int volumes_fd = chase_and_openat(var_lib_fd, "volumes", CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        if (volumes_fd == -ENOENT) {
                volumes_fd = xopenat_full(var_lib_fd, "volumes", O_EXCL|O_CREAT|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW, XO_LABEL|XO_SUBVOLUME, 0700);
                if (volumes_fd == -EEXIST)
                        volumes_fd = chase_and_openat(var_lib_fd, "volumes", CHASE_TRIGGER_AUTOFS|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_DIRECTORY, /* ret_path= */ NULL);
        }
        if (volumes_fd < 0)
                return log_error_errno(volumes_fd, "Failed to open '/var/lib/volumes/': %m");

        return TAKE_FD(volumes_fd);
}

static int vl_method_list(
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

        _cleanup_close_ int fd = open_volumes_dir();
        if (fd < 0)
                return r;

        _cleanup_free_ DirectoryEntries *dentries = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT, &dentries);
        if (r < 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Volumes.NoSuchVolume");
        if (r < 0)
                return r;

        FOREACH_ARRAY(dp, dentries->entries, dentries->n_entries) {
                struct dirent *d = *dp;

                const char *e = endswith(d->d_name, ".volume");
                if (!e)
                        continue;

                if (!IN_SET(d->d_type, DT_REG, DT_DIR, DT_UNKNOWN))
                        continue;

                _cleanup_free_ char *n = strndup(d->d_name, e - d->d_name);
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
                        return log_debug_errno(errno, "Failed to stat() '%s' in volumes directory: %m", d->d_name);
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

        r = sd_varlink_set_sentinel(link, "io.systemd.Volumes.NoSuchTemplate");
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

        return r;
}

static int vl_method_acquire(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

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
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!string_is_safe(p.name, /* flags= */ 0))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (!IN_SET(p.create_mode, CREATE_ANY, CREATE_OPEN, CREATE_NEW))
                return sd_varlink_error(link, "io.systemd.Volumes.CreateNotSupported", NULL);

        Template t = _TEMPLATE_INVALID;
        if (!isempty(p.template)) {
                t = template_from_string(p.template);
                if (t < 0)
                        return sd_varlink_error(link, "io.systemd.Volumes.NoSuchTemplate", NULL);
        }

        if (p.read_only > 0) {
                if (p.create_mode == CREATE_NEW)
                        return sd_varlink_error_invalid_parameter_name(link, "readOnly");

                p.create_mode = CREATE_OPEN;
        }

        /* Add a suffix so that we are never attempted to open a temporary file assuming it was a valid volume */
        _cleanup_free_ char *filename = strjoin(p.name, ".volume");
        if (!filename)
                return log_oom_debug();

        if (!filename_is_valid(filename))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        _cleanup_close_ int volumes_fd = open_volumes_dir();
        if (volumes_fd < 0)
                return volumes_fd;

        _cleanup_close_ int fd = -EBADF;
        bool reopen = false;
        r = chaseat(volumes_fd, filename, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &fd);
        if (r < 0) {
                if (r != -ENOENT || p.create_mode == CREATE_OPEN)
                        return r;

                /* Try to create the volume */
                switch (p.request_as) {

                case VOLUME_DIR: {
                        XOpenFlags xopen_flags;

                        switch (t < 0 ? TEMPLATE_BTRFS_SUBVOLUME : t) {

                        case TEMPLATE_PLAIN_DIRECTORY:
                                xopen_flags = 0;
                                break;

                        case TEMPLATE_BTRFS_SUBVOLUME:
                                xopen_flags = XO_SUBVOLUME;
                                break;

                        default:
                                return sd_varlink_error(link, "io.systemd.Volumes.BadTemplate", NULL);
                        }

                        fd = xopenat_full(volumes_fd, filename, O_EXCL|O_CLOEXEC|O_CREAT|O_DIRECTORY|O_NOFOLLOW, xopen_flags, 0755);
                        if (fd == -EEXIST)
                                break;
                        if (fd < 0)
                                return fd;

                        r = RET_NERRNO(fchown(fd, FOREIGN_UID_MIN, FOREIGN_UID_MIN));
                        if (r < 0) {
                                (void) unlinkat(volumes_fd, filename, AT_REMOVEDIR);
                                return r;
                        }

                        // FIXME: use fsopen to create detached mount that is potentially read-only and covers a single mount only
                        break;
                }

                case VOLUME_REG:
                case VOLUME_BLK: {
                        if (p.create_size == UINT64_MAX)
                                return sd_varlink_error(link, "io.systemd.Volumes.CreateSizeRequired", NULL);

                        bool sparse;
                        switch (t < 0 ? TEMPLATE_SPARSE_BLOCK : t) {

                        case TEMPLATE_SPARSE_BLOCK:
                                sparse = true;
                                break;

                        case TEMPLATE_ALLOCATED_BLOCK:
                                sparse = false;
                                break;

                        default:
                                return sd_varlink_error(link, "io.systemd.Volumes.BadTemplate", NULL);
                        }

                        XOpenFlags xopen_flags = p.read_only < 0 ? XO_AUTO_RW_RO : 0;
                        int open_flags = p.read_only < 0 ? 0 : (p.read_only > 0 ? O_RDONLY : O_RDWR);

                        fd = xopenat_full(volumes_fd, filename, open_flags|O_EXCL|O_CLOEXEC|O_NOFOLLOW, xopen_flags|XO_REGULAR|XO_NOCOW, 0600);
                        if (fd == -EEXIST)
                                break;
                        if (fd < 0)
                                return fd;

                        if (sparse)
                                r = RET_NERRNO(ftruncate(fd, p.create_size));
                        else
                                r = RET_NERRNO(fallocate(fd, /* mode= */ 0, /* offset= */ 0, p.create_size));
                        if (r < 0)
                                return r;

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
                                return sd_varlink_error(link, "io.systemd.Volumes.VolumeExists", NULL);

                        r = chaseat(volumes_fd, filename, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &fd);
                        if (r < 0)
                                return r;

                        reopen = true;
                }
        } else {
                if (p.create_mode == CREATE_NEW)
                        return sd_varlink_error(link, "io.systemd.Volumes.VolumeExists", NULL);

                reopen = true;
        }

        if (reopen) {
                XOpenFlags xopen_flags =
                        (IN_SET(p.request_as, VOLUME_REG, VOLUME_BLK) ? XO_REGULAR : 0) |
                        (p.read_only < 0 ? XO_AUTO_RW_RO : 0);
                int open_flags =
                        (p.request_as == VOLUME_DIR ? O_DIRECTORY : 0) |
                        (p.read_only < 0 ? 0 : (p.read_only > 0 ? O_RDONLY : O_RDWR));

                _cleanup_close_ int reopened_fd = xopenat_full(fd, /* path= */ NULL, open_flags|O_CLOEXEC, xopen_flags, /* mode= */ MODE_INVALID);
                if (reopened_fd < 0)
                        return reopened_fd;

                close_and_replace(fd, reopened_fd);
        }

        int open_flags = fcntl(fd, F_GETFL, 0);
        if (open_flags < 0)
                return -errno;

        struct stat st;
        if (fstat(fd, &st) < 0)
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

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY|
                        SD_VARLINK_SERVER_HANDLE_SIGINT|
                        SD_VARLINK_SERVER_HANDLE_SIGTERM|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_Volumes);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.Volumes.Acquire", vl_method_acquire,
                        "io.systemd.Volumes.List", vl_method_list,
                        "io.systemd.Volumes.ListTemplates", vl_method_list_templates);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}


static int run(int argc, char* argv[]) {
        log_setup();

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
