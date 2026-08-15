/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <fnmatch.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-polkit.h"
#include "chase.h"
#include "chattr-util.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "fs-util.h"
#include "hashmap.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "path-lookup.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "runtime-scope.h"
#include "stat-util.h"
#include "storage-util.h"
#include "string-table.h"
#include "tmpfile-util.h"
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

        _cleanup_close_ int state_fd = chase_and_open(state_dir, /* root= */ NULL, CHASE_TRIGGER_AUTOFS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, O_CLOEXEC|O_CREAT|O_DIRECTORY, /* ret_path= */ NULL);
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

                if (!IN_SET(d->d_type, DT_REG, DT_DIR, DT_LNK, DT_BLK, DT_UNKNOWN))
                        continue;

                const char *e = endswith(d->d_name, ".volume");
                if (!e)
                        continue;

                _cleanup_free_ char *n = strndup(d->d_name, e - d->d_name);
                if (!n)
                        return log_oom_debug();

                if (!storage_volume_name_is_valid(n))
                        continue;

                if (p.match_name && fnmatch(p.match_name, n, FNM_NOESCAPE) != 0)
                        continue;

                _cleanup_close_ int pin_fd = -EBADF;
                r = chaseat(XAT_FDROOT, fd, d->d_name, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &pin_fd);
                if (r < 0) {
                        log_debug_errno(r, "Failed to stat() '%s' in storage directory, ignoring: %m", d->d_name);
                        continue;
                }

                struct stat st;
                if (fstat(pin_fd, &st) < 0)
                        return log_debug_errno(errno, "Failed to stat() '%s' in storage directory: %m", d->d_name);

                uint64_t size = UINT64_MAX, used = UINT64_MAX;
                bool ro = false;

                switch (st.st_mode & S_IFMT) {
                case S_IFREG:
                        ro = (st.st_mode & 0222) == 0;
                        size = st.st_size;
                        used = (uint64_t) st.st_blocks * UINT64_C(512);
                        break;

                case S_IFDIR:
                        r = fd_is_read_only_fs(pin_fd);
                        if (r < 0)
                                log_debug_errno(r, "Failed to determine if '%s' is read-only, ignoring", d->d_name);
                        else
                                ro = r > 0;
                        break;

                case S_IFBLK: {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = sd_device_new_from_stat_rdev(&dev, &st);
                        if (r < 0)
                                log_debug_errno(r, "Failed to acquire device for '%s', ignoring: %m", d->d_name);
                        else {
                                r = device_get_sysattr_bool(dev, "ro");
                                if (r < 0)
                                        log_device_debug_errno(dev, r, "Failed to get read/only state of '%s', ignoring: %m", d->d_name);
                                else
                                        ro = r > 0;

                                r = device_get_sysattr_u64(dev, "size", &size);
                                if (r < 0)
                                        log_device_debug_errno(dev, r, "Failed to acquire size of device '%s', ignoring: %m", d->d_name);
                                else
                                        /* the 'size' sysattr is always in multiples of 512, even on 4K sector block devices! */
                                        assert_se(MUL_ASSIGN_SAFE(&size, 512)); /* Overflow check for coverity */
                        }

                        break;
                }

                default:
                        log_debug("Volume of unexpected inode type, ignoring: %s", d->d_name);
                        continue;
                }

                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", n),
                                SD_JSON_BUILD_PAIR_STRING("type", inode_type_to_string(st.st_mode)),
                                SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", ro),
                                SD_JSON_BUILD_PAIR_CONDITION(size != UINT64_MAX, "sizeBytes", SD_JSON_BUILD_UNSIGNED(size)),
                                SD_JSON_BUILD_PAIR_CONDITION(used != UINT64_MAX, "usedBytes", SD_JSON_BUILD_UNSIGNED(used)));
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

                if (p.match_name && fnmatch(p.match_name, n, FNM_NOESCAPE) != 0)
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

        _cleanup_free_ char *tf = NULL;
        r = tempfn_random(filename, /* extra= */ NULL, &tf);
        if (r < 0)
                return r;

        _cleanup_close_ int volume_fd = xopenat_full(storage_fd, tf, O_CREAT|O_EXCL|O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, xopen_flags, 0700);
        if (volume_fd < 0)
                return volume_fd;

        _cleanup_close_ int root_fd = xopenat_full(volume_fd, "root", O_CREAT|O_EXCL|O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW, xopen_flags, 0755);
        if (root_fd < 0) {
                r = root_fd;
                goto fail;
        }

        r = RET_NERRNO(fchown(root_fd, FOREIGN_UID_MIN, FOREIGN_UID_MIN));
        if (r < 0)
                goto fail;

        r = rename_noreplace(storage_fd, tf, storage_fd, filename);
        if (r < 0)
                goto fail;

        return TAKE_FD(root_fd);

fail:
        if (root_fd >= 0) {
                assert(volume_fd >= 0);
                root_fd = safe_close(root_fd);
                (void) unlinkat(volume_fd, "root", AT_REMOVEDIR);
        }

        if (volume_fd >= 0) {
                volume_fd = safe_close(volume_fd);
                (void) unlinkat(storage_fd, tf, AT_REMOVEDIR);
        }

        return r;
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

        _cleanup_free_ char *tf = NULL;
        _cleanup_close_ int fd = open_tmpfile_linkable_at(storage_fd, filename, O_RDWR|O_CLOEXEC, &tf);
        if (fd < 0)
                return fd;

        CLEANUP_TMPFILE_AT(storage_fd, tf);

        r = chattr_fd(fd, FS_NOCOW_FL, FS_NOCOW_FL);
        if (r < 0 && !ERRNO_IS_IOCTL_NOT_SUPPORTED(r))
                return r;

        if (create_size > 0) {
                if (sparse)
                        r = RET_NERRNO(ftruncate(fd, create_size));
                else
                        r = RET_NERRNO(fallocate(fd, /* mode= */ 0, /* offset= */ 0, create_size));
                if (r < 0)
                        return r;
        }

        r = RET_NERRNO(fchmod(fd, 0600));
        if (r < 0)
                return r;

        r = link_tmpfile_at(fd, storage_fd, tf, filename, /* flags= */ 0);
        if (r < 0)
                return r;

        tf = mfree(tf); /* disarm clean-up */

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
                { "name",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, name),        SD_JSON_MANDATORY },
                { "createMode",      SD_JSON_VARIANT_STRING,        json_dispatch_create_mode,     voffsetof(p, create_mode), 0                 },
                { "template",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, template),    0                 },
                { "readOnly",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     voffsetof(p, read_only),   0                 },
                { "requestAs",       SD_JSON_VARIANT_STRING,        json_dispatch_volume_type,     voffsetof(p, request_as),  0                 },
                { "createSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, create_size), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!storage_volume_name_is_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (!IN_SET(p.create_mode, CREATE_ANY, CREATE_OPEN, CREATE_NEW))
                return sd_varlink_error(link, "io.systemd.StorageProvider.CreateNotSupported", NULL);

        /* off_t is signed, hence refuse overly long requests */
        if (p.create_size != UINT64_MAX && p.create_size > INT64_MAX)
                return sd_varlink_error_invalid_parameter_name(link, "createSizeBytes");

        Template t = _TEMPLATE_INVALID;
        if (!isempty(p.template)) {
                if (!storage_template_name_is_valid(p.template))
                        return sd_varlink_error_invalid_parameter_name(link, "template");

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
         * volume.  */
        _cleanup_free_ char *filename = strjoin(p.name, ".volume");
        if (!filename)
                return log_oom_debug();

        if (!filename_is_valid(filename))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (arg_runtime_scope != RUNTIME_SCOPE_USER) {
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
        }

        _cleanup_close_ int storage_fd = open_storage_dir();
        if (storage_fd < 0)
                return storage_fd;

        _cleanup_close_ int pin_fd = -EBADF, real_fd = -EBADF;
        r = chaseat(XAT_FDROOT, storage_fd, filename, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &pin_fd);
        if (r < 0) {
                if (r != -ENOENT)
                        return r;
                if (p.create_mode == CREATE_OPEN || p.read_only > 0)
                        return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchVolume", NULL);

                /* Doesn't exist yet: create it now */

                if (p.request_as < 0) /* Make a choice: pick default type */
                        p.request_as = t < 0 ? VOLUME_DIR : volume_type_from_template(t);

                /* Try to create the volume */
                switch (p.request_as) {

                case VOLUME_DIR: {

                        if (t < 0) /* Make a choice: pick default template */
                                t = TEMPLATE_SUBVOLUME;

                        real_fd = create_volume_dir(storage_fd, filename, t);
                        break;
                }

                case VOLUME_REG: {
                        if (p.create_size == UINT64_MAX)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.CreateSizeRequired", NULL);

                        if (t < 0) /* Make a choice: pick default template */
                                t = TEMPLATE_SPARSE_FILE;

                        real_fd = create_volume_reg(storage_fd, filename, t, p.create_size);
                        break;
                }

                case VOLUME_BLK:
                        /* We don't support creating block devices, we only support if they are symlinked
                         * into the storage directory. */
                        return sd_varlink_error(link, "io.systemd.StorageProvider.CreateNotSupported", NULL);

                default:
                        assert_not_reached();
                }

                if (real_fd == -ENOMEDIUM)
                        return sd_varlink_error(link, "io.systemd.StorageProvider.BadTemplate", NULL);
                if (real_fd == -EEXIST) {
                        if (p.create_mode == CREATE_NEW)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.VolumeExists", NULL);

                        /* If we failed to open the volume and reached this point, then the volume already
                         * exists by now (i.e. we ran into a race). In that case, try to pin it a second time
                         * (but only once, let's never loop around this). */
                        r = chaseat(XAT_FDROOT, storage_fd, filename, CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &pin_fd);
                        if (r < 0)
                                return r;
                } else if (real_fd < 0)
                        return real_fd;

        } else if (p.create_mode == CREATE_NEW)
                return sd_varlink_error(link, "io.systemd.StorageProvider.VolumeExists", NULL);

        /* At this point, we either already opened the real fd, or we managed to pin it (but not both) */
        assert((real_fd >= 0) != (pin_fd >= 0));

        /* Let's first settle the volume type */
        struct stat st;
        if (fstat(real_fd >= 0 ? real_fd : pin_fd, &st) < 0)
                return -errno;

        if (p.request_as == VOLUME_REG) {
                /* First, check for the other supported types and generate a nice error */
                if (IN_SET(st.st_mode & S_IFMT, S_IFDIR, S_IFBLK))
                        return sd_varlink_error(link, "io.systemd.StorageProvider.WrongType", NULL);

                /* Second verify cover all other types */
                r = stat_verify_regular(&st);
                if (r < 0)
                        return r;
        } else if (p.request_as == VOLUME_DIR) {
                if (IN_SET(st.st_mode & S_IFMT, S_IFREG, S_IFBLK))
                        return sd_varlink_error(link, "io.systemd.StorageProvider.WrongType", NULL);

                r = stat_verify_directory(&st);
                if (r < 0)
                        return r;
        } else if (p.request_as == VOLUME_BLK) {
                if (IN_SET(st.st_mode & S_IFMT, S_IFREG, S_IFDIR))
                        return sd_varlink_error(link, "io.systemd.StorageProvider.WrongType", NULL);

                r = stat_verify_block(&st);
                if (r < 0)
                        return r;

        } else if (S_ISREG(st.st_mode))
                p.request_as = VOLUME_REG;
        else if (S_ISDIR(st.st_mode))
                p.request_as = VOLUME_DIR;
        else if (S_ISBLK(st.st_mode))
                p.request_as = VOLUME_BLK;
        else
                return log_debug_errno(SYNTHETIC_ERRNO(EBADF), "Unexpected inode type, refusing.");

        /* Let's now acquire a real fd for the pinned fd, if we still need to */
        if (real_fd < 0) {
                assert(pin_fd >= 0);

                XOpenFlags xopen_flags =
                        (p.read_only < 0 && !S_ISDIR(st.st_mode) ? XO_AUTO_RW_RO : 0);
                int open_flags =
                        (p.read_only < 0 ? 0 : (p.read_only > 0 || S_ISDIR(st.st_mode) ? O_RDONLY : O_RDWR));

                const char *subdir = NULL;
                if (p.request_as == VOLUME_DIR) {
                        /* We place the root of the directory tree one level down, to separate ownership of
                         * the inode: the upper inode is owned by the host, the lower one by the volume. This
                         * matters so that the host one can be owned by the host's root, and the volume one
                         * by the foreign UID range. */
                        subdir = "root";
                        open_flags |= O_DIRECTORY|O_NOFOLLOW;
                }

                real_fd = xopenat_full(pin_fd, subdir, open_flags|O_CLOEXEC, xopen_flags, /* mode= */ MODE_INVALID);
                if (real_fd < 0)
                        return log_debug_errno(real_fd, "Failed to reopen volume fd for '%s': %m", filename);

                /* In directory mode we might be looking at a different inode node, refresh the stat data */
                if (p.request_as == VOLUME_DIR && fstat(real_fd, &st) < 0)
                        return -errno;
        }

        assert(real_fd >= 0);

        bool ro;
        switch (p.request_as) {

        case VOLUME_REG:
        case VOLUME_BLK: {
                assert(IN_SET(st.st_mode & S_IFMT, S_IFREG, S_IFBLK));

                int open_flags = fcntl(real_fd, F_GETFL, 0);
                if (open_flags < 0)
                        return -errno;

                ro = (open_flags & O_ACCMODE_STRICT) == O_RDONLY;
                break;
        }

        case VOLUME_DIR: {
                assert(S_ISDIR(st.st_mode));

                if (!uid_is_foreign(st.st_uid) ||
                    !gid_is_foreign(st.st_gid))
                        return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "Storage directory not owned by foreign UID/GID range.");

                /* Let's now generate a new mount for the directory tree, where propagation is disabled, and the
                 * flags are all set to good defaults */
                _cleanup_close_ int mount_fd = open_tree_attr_with_fallback(
                                real_fd,
                                /* path= */ NULL,
                                OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW,
                                &(struct mount_attr) {
                                        .attr_set = (p.read_only > 0 ? MOUNT_ATTR_RDONLY : 0),
                                        .attr_clr = MOUNT_ATTR_NOSUID|MOUNT_ATTR_NOEXEC|MOUNT_ATTR_NODEV,
                                        .propagation = MS_PRIVATE,
                                });
                if (mount_fd < 0)
                        return log_debug_errno(mount_fd, "Failed to generate per-volume mount: %m");

                /* Let's turn on propagation again now that it is disconnected, simply because MS_SHARED is
                 * generally the default for everything we return. */

                if (mount_setattr(mount_fd, "", AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,
                                  &(struct mount_attr) {
                                          .propagation = MS_SHARED,
                                  }, MOUNT_ATTR_SIZE_VER0) < 0)
                        return log_debug_errno(errno, "Failed to enable propagation on per-volume mount: %m");

                close_and_replace(real_fd, mount_fd);

                r = fd_is_read_only_fs(real_fd);
                if (r < 0)
                        return r;

                ro = r > 0;
                break;
        }

        default:
                assert_not_reached();
        }

        if (p.read_only == 0 && ro)
                return sd_varlink_error(link, "io.systemd.StorageProvider.ReadOnlyVolume", NULL);

        int idx = sd_varlink_push_fd(link, real_fd);
        if (idx < 0)
                return idx;

        TAKE_FD(real_fd);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("fileDescriptorIndex", idx),
                        SD_JSON_BUILD_PAIR_STRING("type", inode_type_to_string(st.st_mode)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", ro),
                        SD_JSON_BUILD_PAIR_CONDITION(p.request_as == VOLUME_DIR, "baseUID", SD_JSON_BUILD_INTEGER(FOREIGN_UID_BASE)),
                        SD_JSON_BUILD_PAIR_CONDITION(p.request_as == VOLUME_DIR, "baseGID", SD_JSON_BUILD_INTEGER(FOREIGN_UID_BASE)));
}

static int vl_server(void) {
        int r;

        _cleanup_(hashmap_freep) Hashmap *polkit_registry = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_HANDLE_SIGINT|
                        SD_VARLINK_SERVER_HANDLE_SIGTERM|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT|
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
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
        help_abstract("Simple file system backed storage provider");

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_section("Options");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-storage-fs", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_COMMON_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                }

        if (option_parser_get_n_args(&opts) > 0)
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
