/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-json.h"
#include "sd-path.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "bus-get-properties.h"
#include "chase.h"
#include "chattr-util.h"
#include "copy.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-file.h"
#include "env-util.h"
#include "extension-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-setup.h"
#include "id128-util.h"
#include "label-util.h"
#include "lock-util.h"
#include "log.h"
#include "loop-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "namespace-util.h"
#include "nsresource.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "runtime-scope.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "uid-classification.h"
#include "vpick.h"
#include "xattr-util.h"

const char* const image_search_path[_IMAGE_CLASS_MAX] = {
        [IMAGE_MACHINE] =   "/etc/machines\0"              /* only place symlinks here */
                            "/run/machines\0"              /* and here too */
                            "/var/lib/machines\0"          /* the main place for images */
                            "/var/lib/container\0"         /* legacy */
                            "/usr/local/lib/machines\0"
                            "/usr/lib/machines\0",

        [IMAGE_PORTABLE] =  "/etc/portables\0"             /* only place symlinks here */
                            "/run/portables\0"             /* and here too */
                            "/var/lib/portables\0"         /* the main place for images */
                            "/usr/local/lib/portables\0"
                            "/usr/lib/portables\0",

        /* Note that we don't allow storing extensions under /usr/, unlike with other image types. That's
         * because extension images are supposed to extend /usr/, so you get into recursive races, especially
         * with directory-based extensions, as the kernel's OverlayFS explicitly checks for this and errors
         * out with -ELOOP if it finds that a lowerdir= is a child of another lowerdir=. */
        [IMAGE_SYSEXT] =    "/etc/extensions\0"            /* only place symlinks here */
                            "/run/extensions\0"            /* and here too */
                            "/var/lib/extensions\0",       /* the main place for images */

        [IMAGE_CONFEXT] =   "/run/confexts\0"              /* only place symlinks here */
                            "/var/lib/confexts\0"          /* the main place for images */
                            "/usr/local/lib/confexts\0"
                            "/usr/lib/confexts\0",
};

/* Inside the initrd, use a slightly different set of search path (i.e. include .extra/sysext/,
 * /.extra/global_sysext, .extra/confext/, and /.extra/global_confext in extension search dir) */
static const char* const image_search_path_initrd[_IMAGE_CLASS_MAX] = {
        /* (entries that aren't listed here will get the same search path as for the non initrd-case) */

        [IMAGE_SYSEXT] =    "/etc/extensions\0"            /* only place symlinks here */
                            "/run/extensions\0"            /* and here too */
                            "/var/lib/extensions\0"        /* the main place for images */
                            "/.extra/sysext\0"             /* put sysext (per-UKI and global) picked up by systemd-stub */
                            "/.extra/global_sysext\0",     /* last, since not trusted */

        [IMAGE_CONFEXT] =   "/run/confexts\0"              /* only place symlinks here */
                            "/var/lib/confexts\0"          /* the main place for images */
                            "/usr/local/lib/confexts\0"
                            "/.extra/confext\0"            /* put confext (per-UKI and global) picked up by systemd-stub */
                            "/.extra/global_confext\0",    /* last, since not trusted. */
};

static const char* image_class_suffix_table[_IMAGE_CLASS_MAX] = {
        [IMAGE_SYSEXT]  = ".sysext",
        [IMAGE_CONFEXT] = ".confext",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(image_class_suffix, ImageClass);

static const char *const image_root_table[_IMAGE_CLASS_MAX] = {
        [IMAGE_MACHINE]  = "/var/lib/machines",
        [IMAGE_PORTABLE] = "/var/lib/portables",
        [IMAGE_SYSEXT]   = "/var/lib/extensions",
        [IMAGE_CONFEXT]  = "/var/lib/confexts",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(image_root, ImageClass);

static const char *const image_root_runtime_table[_IMAGE_CLASS_MAX] = {
        [IMAGE_MACHINE]  = "/run/machines",
        [IMAGE_PORTABLE] = "/run/portables",
        [IMAGE_SYSEXT]   = "/run/extensions",
        [IMAGE_CONFEXT]  = "/run/confexts",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(image_root_runtime, ImageClass);

static const char *const image_dirname_table[_IMAGE_CLASS_MAX] = {
        [IMAGE_MACHINE]  = "machines",
        [IMAGE_PORTABLE] = "portables",
        [IMAGE_SYSEXT]   = "extensions",
        [IMAGE_CONFEXT]  = "confexts",
};

static const char auxiliary_suffixes_nulstr[] =
        ".nspawn\0"
        ".oci-config\0"
        ".roothash\0"
        ".roothash.p7s\0"
        ".usrhash\0"
        ".usrhash.p7s\0"
        ".verity\0";

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(image_dirname, ImageClass);

static Image* image_free(Image *i) {
        assert(i);

        free(i->name);
        free(i->path);

        free(i->fh);

        free(i->hostname);
        strv_free(i->machine_info);
        strv_free(i->os_release);
        strv_free(i->sysext_release);
        strv_free(i->confext_release);

        return mfree(i);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Image, image, image_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(image_hash_ops, char, string_hash_func, string_compare_func,
                                      Image, image_unref);

static char** image_settings_path(Image *image, RuntimeScope scope) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *fn = NULL;
        size_t i = 0;
        int r;

        assert(image);

        l = new0(char*, 5);
        if (!l)
                return NULL;

        fn = strjoin(image->name, ".nspawn");
        if (!fn)
                return NULL;

        static const uint64_t system_locations[] = {
                SD_PATH_SYSTEM_CONFIGURATION,
                SD_PATH_SYSTEM_RUNTIME,
                SD_PATH_SYSTEM_LIBRARY_PRIVATE,
                _SD_PATH_INVALID
        };
        static const uint64_t user_locations[] = {
                SD_PATH_USER_CONFIGURATION,
                SD_PATH_USER_RUNTIME,
                SD_PATH_USER_LIBRARY_PRIVATE,
                _SD_PATH_INVALID
        };
        const uint64_t *locations;

        switch (scope) {
        case RUNTIME_SCOPE_SYSTEM:
                locations = system_locations;
                break;

        case RUNTIME_SCOPE_USER:
                locations = user_locations;
                break;

        default:
                assert_not_reached();
        }

        for (size_t k = 0; locations[k] != _SD_PATH_INVALID; k++) {
                _cleanup_free_ char *s = NULL;
                r = sd_path_lookup(locations[k], "systemd/nspawn", &s);
                if (r == -ENXIO)
                        continue;
                if (r < 0)
                        return NULL;

                l[i] = path_join(s, fn);
                if (!l[i])
                        return NULL;

                i++;
        }

        r = file_in_same_dir(image->path, fn, l + i);
        if (r == -ENOMEM)
                return NULL;
        if (r < 0)
                log_debug_errno(r, "Failed to generate .nspawn settings path from image path, ignoring: %m");

        strv_uniq(l);

        return TAKE_PTR(l);
}

static int image_auxiliary_path(Image *image, const char *suffix, char **ret) {
        assert(image);
        assert(suffix);

        _cleanup_free_ char *fn = strjoin(image->name, suffix);
        if (!fn)
                return -ENOMEM;

        return file_in_same_dir(image->path, fn, ret);
}

static int image_new(
                ImageType t,
                ImageClass c,
                const char *pretty,
                const char *path,
                bool read_only,
                usec_t crtime,
                usec_t mtime,
                struct file_handle *fh,
                uint64_t on_mount_id,
                uint64_t inode,
                Image **ret) {

        _cleanup_(image_unrefp) Image *i = NULL;

        assert(t >= 0);
        assert(t < _IMAGE_TYPE_MAX);
        assert(pretty);
        assert(path);
        assert(ret);

        i = new(Image, 1);
        if (!i)
                return -ENOMEM;

        *i = (Image) {
                .n_ref = 1,
                .type = t,
                .class = c,
                .read_only = read_only,
                .crtime = crtime,
                .mtime = mtime,
                .on_mount_id = on_mount_id,
                .inode = inode,
                .usage = UINT64_MAX,
                .usage_exclusive = UINT64_MAX,
                .limit = UINT64_MAX,
                .limit_exclusive = UINT64_MAX,
        };

        if (fh) {
                i->fh = file_handle_dup(fh);
                if (!i->fh)
                        return -ENOMEM;
        }

        i->name = strdup(pretty);
        if (!i->name)
                return -ENOMEM;

        i->path = strdup(path);
        if (!i->path)
                return -ENOMEM;

        path_simplify(i->path);

        *ret = TAKE_PTR(i);

        return 0;
}

static int extract_image_basename(
                const char *path,
                const char *class_suffix,  /* e.g. ".sysext" (this is an optional suffix) */
                char **format_suffixes,    /* e.g. ".raw"    (one of these will be required) */
                char **ret_basename,
                char **ret_suffix) {

        _cleanup_free_ char *name = NULL, *suffix = NULL;
        int r;

        assert(path);

        r = path_extract_filename(path, &name);
        if (r < 0)
                return r;

        if (format_suffixes) {
                char *e = endswith_strv(name, format_suffixes);
                if (!e) /* Format suffix is required */
                        return -EINVAL;

                if (ret_suffix) {
                        suffix = strdup(e);
                        if (!suffix)
                                return -ENOMEM;
                }

                *e = 0;
        }

        if (class_suffix) {
                char *e = endswith(name, class_suffix);
                if (e) { /* Class suffix is optional */
                        if (ret_suffix) {
                                _cleanup_free_ char *j = strjoin(e, suffix);
                                if (!j)
                                        return -ENOMEM;

                                free_and_replace(suffix, j);
                        }

                        *e = 0;
                }
        }

        if (!image_name_is_valid(name))
                return -EINVAL;

        if (ret_suffix)
                *ret_suffix = TAKE_PTR(suffix);

        if (ret_basename)
                *ret_basename = TAKE_PTR(name);

        return 0;
}

static int image_update_quota(Image *i, int fd) {
        _cleanup_close_ int fd_close = -EBADF;
        int r;

        assert(i);

        if (image_is_vendor(i) || image_is_host(i))
                return -EROFS;

        if (i->type != IMAGE_SUBVOLUME)
                return -EOPNOTSUPP;

        if (fd < 0) {
                fd_close = open(i->path, O_CLOEXEC|O_DIRECTORY);
                if (fd_close < 0)
                        return -errno;
                fd = fd_close;
        } else {
                /* Convert from O_PATH to proper fd, if needed */
                fd = fd_reopen_condition(fd, O_CLOEXEC|O_DIRECTORY, O_PATH, &fd_close);
                if (fd < 0)
                        return fd;
        }

        r = btrfs_quota_scan_ongoing(fd);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        BtrfsQuotaInfo quota;
        r = btrfs_subvol_get_subtree_quota_fd(fd, 0, &quota);
        if (r < 0)
                return r;

        i->usage = quota.referenced;
        i->usage_exclusive = quota.exclusive;
        i->limit = quota.referenced_max;
        i->limit_exclusive = quota.exclusive_max;

        return 1;
}

static int image_make(
                ImageClass c,
                const char *pretty,
                int fd, /* O_PATH fd */
                const char *path,
                const struct stat *st,
                Image **ret) {

        _cleanup_free_ char *pretty_buffer = NULL;
        bool read_only;
        int r;

        assert(path);
        assert(path_is_absolute(path));

        /* We explicitly *do* follow symlinks here, since we want to allow symlinking trees, raw files and block
         * devices into /var/lib/machines/, and treat them normally.
         * Note that if the caller does not want to follow symlinks (and does not care about symlink races)
         * then the caller should pass in a resolved path and an fd.
         *
         * This function returns -ENOENT if we can't find the image after all, and -EMEDIUMTYPE if it's not a file we
         * recognize. */

        _cleanup_close_ int _fd = -EBADF;
        if (fd < 0) {
                /* If we didn't get an fd passed in, then let's pin it via O_PATH now */
                _fd = open(path, O_PATH|O_CLOEXEC);
                if (_fd < 0)
                        return -errno;

                fd = _fd;
                st = NULL; /* refresh stat() data now that we have the inode pinned */
        }

        struct stat stbuf;
        if (!st) {
                if (fstat(fd, &stbuf) < 0)
                        return -errno;

                st = &stbuf;
        }

        read_only =
                path_startswith(path, "/usr") ||
                (faccessat(fd, "", W_OK, AT_EACCESS|AT_EMPTY_PATH) < 0 && errno == EROFS);

        _cleanup_free_ struct file_handle *fh = NULL;
        uint64_t on_mount_id;
        int _mnt_id;

        /* The fallback is required for CentOS 9 compatibility when working on a directory located on an
         * overlayfs. */
        r = name_to_handle_at_try_fid(fd, /* path= */ NULL, &fh, &_mnt_id, &on_mount_id, AT_EMPTY_PATH);
        if (r < 0) {
                if (is_name_to_handle_at_fatal_error(r))
                        return r;

                r = path_get_unique_mnt_id_at(fd, /* path= */ NULL, &on_mount_id);
                if (r < 0) {
                        if (!ERRNO_IS_NEG_NOT_SUPPORTED(r) && r != -EUNATCH)
                                return r;

                        int on_mount_id_fallback = -1;
                        r = path_get_mnt_id_at(fd, /* path= */ NULL, &on_mount_id_fallback);
                        if (r < 0)
                                return r;

                        on_mount_id = on_mount_id_fallback;
                }
        } else if (r == 0)
                on_mount_id = _mnt_id;

        if (S_ISDIR(st->st_mode)) {

                if (!ret)
                        return 0;

                if (endswith(path, ".mstack")) {
                        usec_t crtime = 0;
                        r = fd_getcrtime(fd, &crtime);
                        if (r < 0)
                                log_debug_errno(r, "Unable to read creation time of '%s', ignoring: %m", path);

                        if (!pretty) {
                                r = extract_image_basename(
                                                path,
                                                image_class_suffix_to_string(c),
                                                STRV_MAKE(".mstack"),
                                                &pretty_buffer,
                                                /* ret_suffix= */ NULL);
                                if (r < 0)
                                        return r;

                                pretty = pretty_buffer;
                        }

                        _cleanup_(mstack_freep) MStack *mstack = NULL;
                        r = mstack_load(path, fd, &mstack);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to load mstack '%s', ignoring: %m", path);
                                read_only = true;
                        } else if (!read_only) {
                                r = mstack_is_read_only(mstack);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to determine if mstack '%s' is read-only, assuming it is: %m", path);

                                read_only = r != 0;
                        }

                        r = image_new(IMAGE_MSTACK,
                                      c,
                                      pretty,
                                      path,
                                      read_only,
                                      crtime,
                                      /* mtime= */ 0,
                                      fh,
                                      on_mount_id,
                                      (uint64_t) st->st_ino,
                                      ret);
                        if (r < 0)
                                return r;

                        if (mstack) {
                                r = mstack_is_foreign_uid_owned(mstack);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to determine if mstack '%s' is foreign UID owned, assuming it is not: %m", path);
                                if (r > 0)
                                        (*ret)->foreign_uid_owned = true;
                        }

                        return 0;
                }

                if (!pretty) {
                        r = extract_image_basename(
                                        path,
                                        image_class_suffix_to_string(c),
                                        /* format_suffixes= */ NULL,
                                        &pretty_buffer,
                                        /* ret_suffix= */ NULL);
                        if (r < 0)
                                return r;

                        pretty = pretty_buffer;
                }

                if (btrfs_might_be_subvol(st)) {

                        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                BtrfsSubvolInfo info;

                                /* It's a btrfs subvolume */

                                r = btrfs_subvol_get_info_fd(fd, 0, &info);
                                if (r < 0)
                                        return r;

                                r = image_new(IMAGE_SUBVOLUME,
                                              c,
                                              pretty,
                                              path,
                                              info.read_only || read_only,
                                              info.otime,
                                              info.ctime,
                                              fh,
                                              on_mount_id,
                                              (uint64_t) st->st_ino,
                                              ret);
                                if (r < 0)
                                        return r;

                                (*ret)->foreign_uid_owned = uid_is_foreign(st->st_uid);
                                (void) image_update_quota(*ret, fd);
                                return 0;
                        }
                }

                /* Get directory creation time (not available everywhere, but that's OK */
                usec_t crtime = 0;
                (void) fd_getcrtime(fd, &crtime);

                /* If the IMMUTABLE bit is set, we consider the directory read-only. Since the ioctl is not
                 * supported everywhere we ignore failures. */
                unsigned file_attr = 0;
                (void) read_attr_fd(fd, &file_attr);

                /* It's just a normal directory. */
                r = image_new(IMAGE_DIRECTORY,
                              c,
                              pretty,
                              path,
                              read_only || (file_attr & FS_IMMUTABLE_FL),
                              crtime,
                              0, /* we don't use mtime of stat() here, since it's not the time of last change of the tree, but only of the top-level dir */
                              fh,
                              on_mount_id,
                              (uint64_t) st->st_ino,
                              ret);
                if (r < 0)
                        return r;

                (*ret)->foreign_uid_owned = uid_is_foreign(st->st_uid);
                return 0;

        } else if (S_ISREG(st->st_mode) && endswith(path, ".raw")) {
                usec_t crtime = 0;

                /* It's a RAW disk image */

                if (!ret)
                        return 0;

                (void) fd_getcrtime(fd, &crtime);

                if (!pretty) {
                        r = extract_image_basename(
                                        path,
                                        image_class_suffix_to_string(c),
                                        STRV_MAKE(".raw"),
                                        &pretty_buffer,
                                        /* ret_suffix= */ NULL);
                        if (r < 0)
                                return r;

                        pretty = pretty_buffer;
                }

                r = image_new(IMAGE_RAW,
                              c,
                              pretty,
                              path,
                              !(st->st_mode & 0222) || read_only,
                              crtime,
                              timespec_load(&st->st_mtim),
                              fh,
                              on_mount_id,
                              (uint64_t) st->st_ino,
                              ret);
                if (r < 0)
                        return r;

                (*ret)->usage = (*ret)->usage_exclusive = st->st_blocks * 512;
                (*ret)->limit = (*ret)->limit_exclusive = st->st_size;

                return 0;

        } else if (S_ISBLK(st->st_mode)) {
                uint64_t size = UINT64_MAX;

                /* A block device */

                if (!ret)
                        return 0;

                if (!pretty) {
                        r = extract_image_basename(
                                        path,
                                        /* class_suffix= */ NULL,
                                        /* format_suffix= */ NULL,
                                        &pretty_buffer,
                                        /* ret_suffix= */ NULL);
                        if (r < 0)
                                return r;

                        pretty = pretty_buffer;
                }

                _cleanup_close_ int block_fd = fd_reopen(fd, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (block_fd < 0)
                        log_debug_errno(errno, "Failed to open block device '%s', ignoring: %m", path);
                else {
                        if (!read_only) {
                                int state = 0;

                                if (ioctl(block_fd, BLKROGET, &state) < 0)
                                        log_debug_errno(errno, "Failed to issue BLKROGET on device '%s', ignoring: %m", path);
                                else if (state)
                                        read_only = true;
                        }

                        r = blockdev_get_device_size(block_fd, &size);
                        if (r < 0)
                                log_debug_errno(r, "Failed to issue BLKGETSIZE64 on device '%s', ignoring: %m", path);

                        block_fd = safe_close(block_fd);
                }

                r = image_new(IMAGE_BLOCK,
                              c,
                              pretty,
                              path,
                              !(st->st_mode & 0222) || read_only,
                              0,
                              0,
                              fh,
                              on_mount_id,
                              (uint64_t) st->st_ino,
                              ret);
                if (r < 0)
                        return r;

                if (!IN_SET(size, 0, UINT64_MAX))
                        (*ret)->usage = (*ret)->usage_exclusive = (*ret)->limit = (*ret)->limit_exclusive = size;

                return 0;
        }

        return -EMEDIUMTYPE;
}

static int pick_image_search_path(
                RuntimeScope scope,
                ImageClass class,
                const char *root,
                char ***ret) {

        int r;

        assert(scope < _RUNTIME_SCOPE_MAX && scope != RUNTIME_SCOPE_GLOBAL);
        assert(class < _IMAGE_CLASS_MAX);
        assert(ret);

        if (class < 0) {
                *ret = NULL;
                return 0;
        }

        if (scope < 0) {
                _cleanup_strv_free_ char **a = NULL, **b = NULL;

                r = pick_image_search_path(RUNTIME_SCOPE_USER, class, root, &a);
                if (r < 0)
                        return r;

                r = pick_image_search_path(RUNTIME_SCOPE_SYSTEM, class, root, &b);
                if (r < 0)
                        return r;

                r = strv_extend_strv(&a, b, /* filter_duplicates= */ false);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(a);
                return 0;
        }

        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM: {
                const char *ns;
                bool is_initrd;

                r = chase_and_access("/etc/initrd-release", root, CHASE_PREFIX_ROOT, F_OK, /* ret_path= */ NULL);
                if (r < 0 && r != -ENOENT)
                        return r;
                is_initrd = r >= 0;

                /* Use the initrd search path if there is one, otherwise use the common one */
                ns = is_initrd && image_search_path_initrd[class] ?
                        image_search_path_initrd[class] :
                        image_search_path[class];
                if (!ns)
                        break;

                _cleanup_strv_free_ char **search = strv_split_nulstr(ns);
                if (!search)
                        return -ENOMEM;

                *ret = TAKE_PTR(search);
                return 0;
        }

        case RUNTIME_SCOPE_USER: {
                if (!IN_SET(class, IMAGE_MACHINE, IMAGE_PORTABLE))
                        break;

                static const uint64_t dirs[] = {
                        SD_PATH_USER_RUNTIME,
                        SD_PATH_USER_STATE_PRIVATE,
                        SD_PATH_USER_LIBRARY_PRIVATE,
                };

                _cleanup_strv_free_ char **search = NULL;
                FOREACH_ELEMENT(d, dirs) {
                        _cleanup_free_ char *p = NULL;

                        r = sd_path_lookup(*d, image_dirname_to_string(class), &p);
                        if (r == -ENXIO) /* No XDG_RUNTIME_DIR set */
                                continue;
                        if (r < 0)
                                return r;

                        r = strv_consume(&search, TAKE_PTR(p));
                        if (r < 0)
                                return r;
                }

                *ret = TAKE_PTR(search);
                return 0;
        }

        default:
                assert_not_reached();
        }

        *ret = NULL;
        return 0;
}

static char** make_possible_filenames(ImageClass class, const char *image_name) {
        _cleanup_strv_free_ char **l = NULL;

        assert(image_name);

        FOREACH_STRING(v_suffix, "", ".v")
                FOREACH_STRING(format_suffix, "", ".raw", ".mstack") {
                        _cleanup_free_ char *j = NULL;
                        const char *class_suffix;

                        class_suffix = image_class_suffix_to_string(class);
                        if (class_suffix) {
                                j = strjoin(image_name, class_suffix, format_suffix, v_suffix);
                                if (!j)
                                        return NULL;

                                if (strv_consume(&l, TAKE_PTR(j)) < 0)
                                        return NULL;
                        }

                        j = strjoin(image_name, format_suffix, v_suffix);
                        if (!j)
                                return NULL;

                        if (strv_consume(&l, TAKE_PTR(j)) < 0)
                                return NULL;
                }

        return TAKE_PTR(l);
}

int image_find(RuntimeScope scope,
               ImageClass class,
               const char *name,
               const char *root,
               Image **ret) {

        int r;

        assert(scope < _RUNTIME_SCOPE_MAX && scope != RUNTIME_SCOPE_GLOBAL);
        assert(class >= 0);
        assert(class < _IMAGE_CLASS_MAX);
        assert(name);

        /* There are no images with invalid names */
        if (!image_name_is_valid(name))
                return -ENOENT;

        _cleanup_strv_free_ char **names = make_possible_filenames(class, name);
        if (!names)
                return -ENOMEM;

        _cleanup_close_ int rfd = XAT_FDROOT; /* We only expect absolute paths */
        if (root) {
                rfd = open(root, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (rfd < 0)
                        return log_debug_errno(errno, "Failed to open root directory '%s': %m", root);
        }

        _cleanup_strv_free_ char **search = NULL;
        r = pick_image_search_path(scope, class, root, &search);
        if (r < 0)
                return r;

        STRV_FOREACH(s, search) {
                _cleanup_closedir_ DIR *d = NULL;
                _cleanup_free_ char *search_path = NULL;

                r = chase_and_opendirat(rfd, *s, CHASE_AT_RESOLVE_IN_ROOT, &search_path, &d);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                STRV_FOREACH(n, names) {
                        const char *fname = *n;
                        _cleanup_free_ char *fname_path = NULL, *chased_path = NULL, *resolved_file = NULL;
                        _cleanup_close_ int fd = -EBADF;

                        fname_path = path_join(search_path, fname);
                        if (!fname_path)
                                return -ENOMEM;

                        /* Follow symlinks only inside given root */
                        r = chaseat(rfd, fname_path, CHASE_AT_RESOLVE_IN_ROOT, &chased_path, &fd);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0)
                                return r;

                        r = chaseat_prefix_root(chased_path, root, &resolved_file);
                        if (r < 0)
                                return r;

                        struct stat st;
                        if (fstat(fd, &st) < 0)
                                return -errno;

                        if (endswith(fname, ".raw")) {
                                if (!S_ISREG(st.st_mode)) {
                                        log_debug("Ignoring non-regular file '%s' with .raw suffix.", fname);
                                        continue;
                                }
                        } else if (endswith(fname, ".mstack")) {

                                if (!S_ISDIR(st.st_mode)) {
                                        log_debug("Ignoring non-directory '%s' with .mstack suffix.", fname);
                                        continue;
                                }

                        } else if (endswith(fname, ".v")) {

                                if (!S_ISDIR(st.st_mode)) {
                                        log_debug("Ignoring non-directory file '%s' with .v suffix.", fname);
                                        continue;
                                }

                                _cleanup_free_ char *suffix = NULL;
                                suffix = strdup(ASSERT_PTR(startswith(fname, name)));
                                if (!suffix)
                                        return -ENOMEM;

                                *ASSERT_PTR(endswith(suffix, ".v")) = 0;

                                PickFilter filter = {
                                        .type_mask = endswith(suffix, ".raw") ? (UINT32_C(1) << DT_REG) | (UINT32_C(1) << DT_BLK) : (UINT32_C(1) << DT_DIR),
                                        .basename = name,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .suffix = suffix,
                                };

                                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                                r = path_pick(root,
                                              rfd,
                                              fname_path, /* This has to be the unresolved entry with the .v suffix */
                                              &filter,
                                              /* n_filters= */ 1,
                                              PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                                              &result);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to pick versioned image on '%s%s', skipping: %m", empty_to_root(root), skip_leading_slash(fname_path));
                                        continue;
                                }
                                if (!result.path) {
                                        log_debug("Found versioned directory '%s%s', without matching entry, skipping.", empty_to_root(root), skip_leading_slash(fname_path));
                                        continue;
                                }

                                /* Refresh the stat data for the discovered target */
                                st = result.st;
                                close_and_replace(fd, result.fd);
                                free(resolved_file);
                                resolved_file = path_join(root, result.path);
                                if (!resolved_file)
                                        return -ENOMEM;

                                /* fname and fname_path are invalid now because they would need to be set
                                 * from result.path by extracting the filename to set
                                 * fname = path_join(fname, filename) and then
                                 * fname_path = path_join(*s, fname) but since they are unused we don't do it */
                                fname = NULL;
                                fname_path = mfree(fname_path);
                        } else if (!S_ISDIR(st.st_mode) && !S_ISBLK(st.st_mode)) {
                                log_debug("Ignoring non-directory and non-block device file '%s' without suffix.", fname);
                                continue;
                        }

                        /* Only put resolved paths into the image entry (incl. --root=).
                         * Defending against symlink races is not done
                         * and would be a TODO. */
                        r = image_make(class, name, fd, resolved_file, &st, ret);
                        if (IN_SET(r, -ENOENT, -EMEDIUMTYPE))
                                continue;
                        if (r < 0)
                                return r;

                        if (ret)
                                (*ret)->discoverable = true;

                        return 1;
                }
        }

        if (scope == RUNTIME_SCOPE_SYSTEM && class == IMAGE_MACHINE && streq(name, ".host")) {
                r = image_make(class,
                               ".host",
                               /* fd= */ -EBADF,
                               /* path= */ empty_to_root(root),
                               /* st= */ NULL,
                               ret);
                if (r < 0)
                        return r;

                if (ret)
                        (*ret)->discoverable = true;

                return 1;
        }

        return -ENOENT;
};

int image_from_path(const char *path, Image **ret) {
        int r;

        /* Note that we don't set the 'discoverable' field of the returned object, because we don't check here whether
         * the image is in the image search path. And if it is we don't know if the path we used is actually not
         * overridden by another, different image earlier in the search path */

        if (path_equal(path, "/"))
                return image_make(
                                IMAGE_MACHINE,
                                ".host",
                                /* fd= */ -EBADF,
                                /* path= */ "/",
                                /* st= */ NULL,
                                ret);

        _cleanup_free_ char *absolute = NULL;
        r = path_make_absolute_cwd(path, &absolute);
        if (r < 0)
                return r;

        return image_make(
                        _IMAGE_CLASS_INVALID,
                        /* pretty= */ NULL,
                        /* fd= */ -EBADF,
                        absolute,
                        /* st= */ NULL,
                        ret);
}

int image_find_harder(
                RuntimeScope scope,
                ImageClass class,
                const char *name_or_path,
                const char *root,
                Image **ret) {

        if (image_name_is_valid(name_or_path))
                return image_find(scope, class, name_or_path, root, ret);

        return image_from_path(name_or_path, ret);
}

int image_discover(
                RuntimeScope scope,
                ImageClass class,
                const char *root,
                Hashmap **images) {

        int r;

        assert(scope < _RUNTIME_SCOPE_MAX && scope != RUNTIME_SCOPE_GLOBAL);
        assert(class >= 0);
        assert(class < _IMAGE_CLASS_MAX);
        assert(images);

        _cleanup_close_ int rfd = XAT_FDROOT;  /* We only expect absolute paths */
        if (root) {
                rfd = open(root, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (rfd < 0)
                        return log_debug_errno(errno, "Failed to open root directory '%s': %m", root);
        }

        _cleanup_strv_free_ char **search = NULL;
        r = pick_image_search_path(scope, class, root, &search);
        if (r < 0)
                return r;

        STRV_FOREACH(s, search) {
                _cleanup_closedir_ DIR *d = NULL;
                _cleanup_free_ char *search_path = NULL;

                r = chase_and_opendirat(rfd, *s, CHASE_AT_RESOLVE_IN_ROOT, &search_path, &d);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                FOREACH_DIRENT_ALL(de, d, return -errno) {
                        _cleanup_free_ char *pretty = NULL, *fname_path = NULL, *chased_path = NULL, *resolved_file = NULL;
                        _cleanup_(image_unrefp) Image *image = NULL;
                        const char *fname = de->d_name;
                        _cleanup_close_ int fd = -EBADF;

                        if (dot_or_dot_dot(fname))
                                continue;

                        fname_path = path_join(search_path, fname);
                        if (!fname_path)
                                return -ENOMEM;

                        /* Follow symlinks only inside given root */
                        r = chaseat(rfd, fname_path, CHASE_AT_RESOLVE_IN_ROOT, &chased_path, &fd);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0)
                                return r;

                        r = chaseat_prefix_root(chased_path, root, &resolved_file);
                        if (r < 0)
                                return r;

                        struct stat st;
                        if (fstat(fd, &st) < 0)
                                return -errno;

                        if (S_ISREG(st.st_mode)) {
                                r = extract_image_basename(
                                                fname,
                                                image_class_suffix_to_string(class),
                                                STRV_MAKE(".raw"),
                                                &pretty,
                                                /* ret_suffix= */ NULL);
                                if (r < 0) {
                                        log_debug_errno(r, "Skipping directory entry '%s', which doesn't look like an image.", fname);
                                        continue;
                                }
                        } else if (S_ISDIR(st.st_mode)) {
                                const char *v;

                                v = endswith(fname, ".v");
                                if (v) {
                                        _cleanup_free_ char *suffix = NULL, *nov = NULL;

                                        nov = strndup(fname, v - fname); /* Chop off the .v */
                                        if (!nov)
                                                return -ENOMEM;

                                        r = extract_image_basename(
                                                        nov,
                                                        image_class_suffix_to_string(class),
                                                        STRV_MAKE(".raw", ".mstack", ""),
                                                        &pretty,
                                                        &suffix);
                                        if (r < 0) {
                                                log_debug_errno(r, "Skipping directory entry '%s', which doesn't look like a versioned image.", fname);
                                                continue;
                                        }

                                        PickFilter filter = {
                                                .type_mask = endswith(suffix, ".raw") ? (UINT32_C(1) << DT_REG) | (UINT32_C(1) << DT_BLK) : (UINT32_C(1) << DT_DIR),
                                                .basename = pretty,
                                                .architecture = _ARCHITECTURE_INVALID,
                                                .suffix = suffix,
                                        };

                                        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                                        r = path_pick(root,
                                                      rfd,
                                                      fname_path, /* This has to be the unresolved entry with the .v suffix */
                                                      &filter,
                                                      /* n_filters= */ 1,
                                                      PICK_ARCHITECTURE|PICK_TRIES|PICK_RESOLVE,
                                                      &result);
                                        if (r < 0) {
                                                log_debug_errno(r, "Failed to pick versioned image on '%s%s', skipping: %m", empty_to_root(root), skip_leading_slash(fname_path));
                                                continue;
                                        }
                                        if (!result.path) {
                                                log_debug("Found versioned directory '%s%s', without matching entry, skipping.", empty_to_root(root), skip_leading_slash(fname_path));
                                                continue;
                                        }

                                        /* Refresh the stat data for the discovered target */
                                        st = result.st;
                                        close_and_replace(fd, result.fd);
                                        free(resolved_file);
                                        resolved_file = path_join(root, result.path);
                                        if (!resolved_file)
                                                return -ENOMEM;

                                        /* fname and fname_path are invalid now because they would need to
                                         * be set from result.path by extracting the filename to set
                                         * fname = path_join(fname, filename) and then
                                         * fname_path = path_join(*s, fname) but since they are unused we
                                         * don't do it */
                                         fname = NULL;
                                         fname_path = mfree(fname_path);
                                } else {
                                        r = extract_image_basename(
                                                        fname,
                                                        image_class_suffix_to_string(class),
                                                        STRV_MAKE(".mstack", ""),
                                                        &pretty,
                                                        /* ret_suffix= */ NULL);
                                        if (r < 0) {
                                                log_debug_errno(r, "Skipping directory entry '%s', which doesn't look like an image.", fname);
                                                continue;
                                        }
                                }

                        } else if (S_ISBLK(st.st_mode)) {
                                r = extract_image_basename(
                                                fname,
                                                /* class_suffix= */ NULL,
                                                /* format_suffix= */ NULL,
                                                &pretty,
                                                /* ret_suffix= */ NULL);
                                if (r < 0) {
                                        log_debug_errno(r, "Skipping directory entry '%s', which doesn't look like an image.", fname);
                                        continue;
                                }
                        } else {
                                log_debug("Skipping directory entry '%s', which is neither regular file, directory nor block device.", fname);
                                continue;
                        }

                        if (hashmap_contains(*images, pretty))
                                continue;

                        /* Only put resolved paths into the image entry.
                         * Defending against symlink races is not done
                         * and would be a TODO. */
                        r = image_make(class, pretty, fd, resolved_file, &st, &image);
                        if (IN_SET(r, -ENOENT, -EMEDIUMTYPE))
                                continue;
                        if (r < 0)
                                return r;

                        image->discoverable = true;

                        r = hashmap_ensure_put(images, &image_hash_ops, image->name, image);
                        if (r < 0)
                                return r;

                        TAKE_PTR(image);
                }
        }

        if (scope == RUNTIME_SCOPE_SYSTEM && class == IMAGE_MACHINE && !hashmap_contains(*images, ".host")) {
                _cleanup_(image_unrefp) Image *image = NULL;

                r = image_make(IMAGE_MACHINE,
                               ".host",
                               /* fd= */ -EBADF,
                               /* path= */ empty_to_root(root),
                               /* st= */ NULL,
                               &image);
                if (r < 0)
                        return r;

                image->discoverable = true;

                r = hashmap_ensure_put(images, &image_hash_ops, image->name, image);
                if (r < 0)
                        return r;

                image = NULL;
        }

        return 0;
}

static int unpriv_remove_cb(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        int r, userns_fd = PTR_TO_FD(userdata);

        assert(sx);

        if (event == RECURSE_DIR_ENTER &&
            S_ISDIR(sx->stx_mode) &&
            uid_is_foreign(sx->stx_uid)) {

                /* This is owned by the foreign UID range, and a dir, let's remove it via mountfsd userns
                 * shenanigans. */

                _cleanup_close_ int tree_fd = -EBADF;
                r = mountfsd_mount_directory_fd(
                                /* vl= */ NULL,
                                inode_fd,
                                userns_fd,
                                DISSECT_IMAGE_FOREIGN_UID,
                                &tree_fd);
                if (r < 0)
                        return r;

                /* Fork off child that moves into userns and does the copying */
                r = pidref_safe_fork_full(
                                "rm-tree",
                                /* stdio_fds= */ NULL,
                                (int[]) { userns_fd, tree_fd, }, 2,
                                FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_REOPEN_LOG,
                                /* ret= */ NULL);
                if (r < 0)
                        log_debug_errno(r, "Process that was supposed to remove subtree '%s' failed, ignoring: %m", empty_to_root(path));
                else if (r == 0) {
                        /* child */

                        r = namespace_enter(
                                        /* pidns_fd= */ -EBADF,
                                        /* mntns_fd= */ -EBADF,
                                        /* netns_fd= */ -EBADF,
                                        userns_fd,
                                        /* root_fd= */ -EBADF);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to join user namespace: %m");
                                _exit(EXIT_FAILURE);
                        }

                        _cleanup_close_ int dfd = fd_reopen(tree_fd, O_DIRECTORY|O_CLOEXEC);
                        if (dfd < 0) {
                                log_error_errno(r, "Failed to reopen tree fd: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = rm_rf_children(dfd, REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD, /* root_dev= */ NULL);
                        if (r < 0) {
                                log_error_errno(r, "Failed to empty '%s' directory in foreign UID mode: %m", empty_to_root(path));
                                _exit(EXIT_FAILURE);
                        }

                        _exit(EXIT_SUCCESS);
                }

                /* Don't descent further into this one, and delete it immediately */
                return RECURSE_DIR_UNLINK_GRACEFUL;
        }

        /* Everything else try to remove */
        if (event == RECURSE_DIR_LEAVE)
                return RECURSE_DIR_UNLINK_GRACEFUL;

        return RECURSE_DIR_CONTINUE;
}

static int unprivileged_remove(Image *i) {
        int r;

        assert(i);

        /* We want this to work in complex .mstack/ hierarchies, where the main directory (and maybe a .v/
         * directory below or two) might be owned by the user themselves, but some subdirs might be owned by
         * the foreign UID range. We deal with this by recursively descending down the tree, and removing
         * foreign-owned ranges via userns shenanigans, and the rest just like that. */

        _cleanup_close_ int userns_fd = nsresource_allocate_userns(
                        /* vl= */ NULL,
                        /* name= */ NULL,
                        /* size= */ NSRESOURCE_UIDS_64K);
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to allocate transient user namespace: %m");

        r = recurse_dir_at(
                        AT_FDCWD,
                        i->path,
                        /* statx_mask= */ STATX_TYPE|STATX_UID,
                        /* n_depth_max= */ UINT_MAX,
                        RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_SAME_MOUNT|RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL,
                        unpriv_remove_cb,
                        FD_TO_PTR(userns_fd));
        if (r < 0)
                return r;

        return 0;
}

int image_remove(Image *i, RuntimeScope scope) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **settings = NULL;
        int r;

        assert(i);

        if (image_is_vendor(i) || image_is_host(i))
                return -EROFS;

        settings = image_settings_path(i, scope);
        if (!settings)
                return -ENOMEM;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(scope, i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:

                /* Let's unlink first, maybe it is a symlink? If that works we are happy. Otherwise, let's get out the
                 * big guns */
                if (unlink(i->path) < 0) {
                        r = btrfs_subvol_remove(i->path, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                        if (r < 0)
                                return r;
                }

                break;

        case IMAGE_DIRECTORY:
                /* Allow deletion of read-only directories */
                (void) chattr_path(i->path, 0, FS_IMMUTABLE_FL);

                _fallthrough_;

        case IMAGE_MSTACK:
                /* If this is foreign owned, try an unprivileged remove first, but accept if that doesn't work, and do it directly either way, maybe it works */
                if (i->foreign_uid_owned)
                        (void) unprivileged_remove(i);

                r = rm_rf(i->path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                if (r < 0)
                        return r;

                break;

        case IMAGE_BLOCK:

                /* If this is inside of /dev, then it's a real block device, hence let's not touch the device node
                 * itself (but let's remove the stuff stored alongside it). If it's anywhere else, let's try to unlink
                 * the thing (it's most likely a symlink after all). */

                if (path_startswith(i->path, "/dev"))
                        break;

                _fallthrough_;
        case IMAGE_RAW:
                if (unlink(i->path) < 0)
                        return -errno;
                break;

        default:
                return -EOPNOTSUPP;
        }

        STRV_FOREACH(j, settings)
                if (unlink(*j) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to unlink %s, ignoring: %m", *j);

        NULSTR_FOREACH(suffix, auxiliary_suffixes_nulstr) {
                _cleanup_free_ char *aux = NULL;
                r = image_auxiliary_path(i, suffix, &aux);
                if (r < 0)
                        return r;

                if (unlink(aux) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to unlink %s, ignoring: %m", aux);
        }

        return 0;
}

static int rename_auxiliary_file(const char *path, const char *new_name, const char *suffix) {
        int r;

        assert(path);
        assert(new_name);
        assert(suffix);

        _cleanup_free_ char *fn = strjoin(new_name, suffix);
        if (!fn)
                return -ENOMEM;

        _cleanup_free_ char *rs = NULL;
        r = file_in_same_dir(path, fn, &rs);
        if (r < 0)
                return r;

        return rename_noreplace(AT_FDCWD, path, AT_FDCWD, rs);
}

int image_rename(Image *i, const char *new_name, RuntimeScope scope) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT, name_lock = LOCK_FILE_INIT;
        _cleanup_free_ char *new_path = NULL, *nn = NULL;
        _cleanup_strv_free_ char **settings = NULL;
        unsigned file_attr = 0;
        int r;

        assert(i);

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        if (image_is_vendor(i) || image_is_host(i))
                return -EROFS;

        settings = image_settings_path(i, scope);
        if (!settings)
                return -ENOMEM;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(scope, i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        /* Make sure nobody takes the new name, between the time we
         * checked it is currently unused in all search paths, and the
         * time we take possession of it */
        r = image_name_lock(scope, new_name, LOCK_EX|LOCK_NB, &name_lock);
        if (r < 0)
                return r;

        r = image_find(scope, IMAGE_MACHINE, new_name, NULL, NULL);
        if (r >= 0)
                return -EEXIST;
        if (r != -ENOENT)
                return r;

        switch (i->type) {

        case IMAGE_DIRECTORY:
                /* Turn of the immutable bit while we rename the image, so that we can rename it */
                (void) read_attr_at(AT_FDCWD, i->path, &file_attr);

                if (file_attr & FS_IMMUTABLE_FL)
                        (void) chattr_path(i->path, 0, FS_IMMUTABLE_FL);

                _fallthrough_;
        case IMAGE_SUBVOLUME:
                r = file_in_same_dir(i->path, new_name, &new_path);
                break;

        case IMAGE_BLOCK:

                /* Refuse renaming raw block devices in /dev, the names are picked by udev after all. */
                if (path_startswith(i->path, "/dev"))
                        return -EROFS;

                r = file_in_same_dir(i->path, new_name, &new_path);
                break;

        case IMAGE_RAW: {
                const char *fn;

                fn = strjoina(new_name, ".raw");

                r = file_in_same_dir(i->path, fn, &new_path);
                break;
        }

        default:
                return -EOPNOTSUPP;
        }
        if (r < 0)
                return r;

        nn = strdup(new_name);
        if (!nn)
                return -ENOMEM;

        r = rename_noreplace(AT_FDCWD, i->path, AT_FDCWD, new_path);
        if (r < 0)
                return r;

        /* Restore the immutable bit, if it was set before */
        if (file_attr & FS_IMMUTABLE_FL)
                (void) chattr_path(new_path, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL);

        free_and_replace(i->path, new_path);
        free_and_replace(i->name, nn);

        STRV_FOREACH(j, settings) {
                r = rename_auxiliary_file(*j, new_name, ".nspawn");
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to rename settings file %s, ignoring: %m", *j);
        }

        NULSTR_FOREACH(suffix, auxiliary_suffixes_nulstr) {
                _cleanup_free_ char *aux = NULL;
                r = image_auxiliary_path(i, suffix, &aux);
                if (r < 0)
                        return r;

                r = rename_auxiliary_file(aux, new_name, suffix);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to rename roothash file %s, ignoring: %m", aux);
        }

        return 0;
}

static int clone_auxiliary_file(const char *path, const char *new_name, const char *suffix) {
        int r;

        assert(path);
        assert(new_name);
        assert(suffix);

        _cleanup_free_ char *fn = strjoin(new_name, suffix);
        if (!fn)
                return -ENOMEM;

        _cleanup_free_ char *rs = NULL;
        r = file_in_same_dir(path, fn, &rs);
        if (r < 0)
                return r;

        return copy_file_atomic(path, rs, 0664, COPY_REFLINK);
}

static int get_pool_directory(
                RuntimeScope scope,
                ImageClass class,
                const char *fname,
                const char *suffix,
                char **ret) {

        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(class >= 0);
        assert(class < _IMAGE_CLASS_MAX);
        assert(ret);

        _cleanup_free_ char *root = NULL;
        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM:
                r = sd_path_lookup(SD_PATH_SYSTEM_STATE_PRIVATE, /* suffix= */ NULL, &root);
                break;

        case RUNTIME_SCOPE_USER:
                r = sd_path_lookup(SD_PATH_USER_STATE_PRIVATE, /* suffix= */ NULL, &root);
                break;

        default:
                return -EOPNOTSUPP;
        }
        if (r < 0)
                return r;

        const char *n = image_dirname_to_string(class);
        if (!n)
                return -EOPNOTSUPP;

        _cleanup_free_ char *j = NULL;
        const char *fn;
        if (fname && suffix) {
                j = strjoin(fname, suffix);
                if (!j)
                        return -ENOMEM;
                fn = j;
        } else
                fn = fname ?: suffix;

        _cleanup_free_ char *p = path_join(root, n, fn);
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
        return 0;
}

static int unprivileged_clone(Image *i, const char *new_path) {
        int r;

        assert(i);
        assert(new_path);

        _cleanup_close_ int userns_fd = nsresource_allocate_userns(
                        /* vl= */ NULL,
                        /* name= */ NULL,
                        /* size= */ NSRESOURCE_UIDS_64K);
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to allocate transient user namespace: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        r = mountfsd_connect(&link);
        if (r < 0)
                return r;

        /* Map original image */
        _cleanup_close_ int tree_fd = -EBADF;
        r = mountfsd_mount_directory(
                        link,
                        i->path,
                        userns_fd,
                        DISSECT_IMAGE_FOREIGN_UID,
                        &tree_fd);
        if (r < 0)
                return r;

        /* Make new image */
        _cleanup_close_ int new_fd = -EBADF;
        r = mountfsd_make_directory(
                        link,
                        new_path,
                        MODE_INVALID,
                        /* flags= */ 0,
                        &new_fd);
        if (r < 0)
                return 0;

        /* Mount new image */
        _cleanup_close_ int target_fd = -EBADF;
        r = mountfsd_mount_directory_fd(
                        link,
                        new_fd,
                        userns_fd,
                        DISSECT_IMAGE_FOREIGN_UID,
                        &target_fd);
        if (r < 0)
                return r;

        link = sd_varlink_unref(link);

        /* Fork off child that moves into userns and does the copying */
        return copy_tree_at_foreign(tree_fd, target_fd, userns_fd);
}

int image_clone(Image *i, const char *new_name, bool read_only, RuntimeScope scope) {
        _cleanup_(release_lock_file) LockFile name_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **settings = NULL;
        int r;

        assert(i);

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        settings = image_settings_path(i, scope);
        if (!settings)
                return -ENOMEM;

        /* Make sure nobody takes the new name, between the time we
         * checked it is currently unused in all search paths, and the
         * time we take possession of it */
        r = image_name_lock(scope, new_name, LOCK_EX|LOCK_NB, &name_lock);
        if (r < 0)
                return r;

        r = image_find(scope, i->class, new_name, NULL, NULL);
        if (r >= 0)
                return -EEXIST;
        if (r != -ENOENT)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:
        case IMAGE_DIRECTORY: {
                /* If we can we'll always try to create a new btrfs subvolume here, even if the source is a plain
                 * directory. */

                _cleanup_free_ char *new_path = NULL;
                r = get_pool_directory(scope, i->class, new_name, /* suffix= */ NULL, &new_path);
                if (r < 0)
                        return r;

                if (i->foreign_uid_owned)
                        r = unprivileged_clone(i, new_path);
                else {
                        r = btrfs_subvol_snapshot_at(
                                        AT_FDCWD, i->path,
                                        AT_FDCWD, new_path,
                                        (read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                        BTRFS_SNAPSHOT_FALLBACK_COPY |
                                        BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                        BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE |
                                        BTRFS_SNAPSHOT_RECURSIVE |
                                        BTRFS_SNAPSHOT_QUOTA);
                        if (r >= 0)
                                /* Enable "subtree" quotas for the copy, if we didn't copy any quota from the source. */
                                (void) btrfs_subvol_auto_qgroup(new_path, /* subvol_id= */ 0, /* create_intermediary_qgroup= */ true);
                }

                break;
        }

        case IMAGE_RAW: {
                _cleanup_free_ char *new_path = NULL;
                r = get_pool_directory(scope, i->class, new_name, ".raw", &new_path);
                if (r < 0)
                        return r;

                r = copy_file_atomic(i->path, new_path, read_only ? 0444 : 0644,
                                     COPY_REFLINK|COPY_CRTIME|COPY_NOCOW_AFTER);
                break;
        }

        case IMAGE_BLOCK:
        default:
                return -EOPNOTSUPP;
        }
        if (r < 0)
                return r;

        STRV_FOREACH(j, settings) {
                r = clone_auxiliary_file(*j, new_name, ".nspawn");
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to clone settings %s, ignoring: %m", *j);
        }

        NULSTR_FOREACH(suffix, auxiliary_suffixes_nulstr) {
                _cleanup_free_ char *aux = NULL;
                r = image_auxiliary_path(i, suffix, &aux);
                if (r < 0)
                        return r;

                r = clone_auxiliary_file(aux, new_name, suffix);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to clone root hash file %s, ignoring: %m", aux);
        }

        return 0;
}

int image_read_only(Image *i, bool b, RuntimeScope scope) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        int r;

        assert(i);

        if (image_is_vendor(i) || image_is_host(i) || image_is_hidden(i))
                return -EROFS;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(scope, i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:

                /* Note that we set the flag only on the top-level
                 * subvolume of the image. */

                r = btrfs_subvol_set_read_only(i->path, b);
                if (r < 0)
                        return r;

                break;

        case IMAGE_DIRECTORY:
                /* For simple directory trees we cannot use the access
                   mode of the top-level directory, since it has an
                   effect on the container itself.  However, we can
                   use the "immutable" flag, to at least make the
                   top-level directory read-only. It's not as good as
                   a read-only subvolume, but at least something, and
                   we can read the value back. */

                r = chattr_path(i->path, b ? FS_IMMUTABLE_FL : 0, FS_IMMUTABLE_FL);
                if (r < 0)
                        return r;

                break;

        case IMAGE_RAW: {
                struct stat st;

                if (stat(i->path, &st) < 0)
                        return -errno;

                if (chmod(i->path, (st.st_mode & 0444) | (b ? 0000 : 0200)) < 0)
                        return -errno;

                /* If the images is now read-only, it's a good time to
                 * defrag it, given that no write patterns will
                 * fragment it again. */
                if (b)
                        (void) btrfs_defrag(i->path);
                break;
        }

        case IMAGE_BLOCK: {
                _cleanup_close_ int fd = -EBADF;
                struct stat st;
                int state = b;

                fd = open(i->path, O_CLOEXEC|O_RDONLY|O_NONBLOCK|O_NOCTTY);
                if (fd < 0)
                        return -errno;

                if (fstat(fd, &st) < 0)
                        return -errno;
                if (!S_ISBLK(st.st_mode))
                        return -ENOTTY;

                if (ioctl(fd, BLKROSET, &state) < 0)
                        return -errno;

                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        i->read_only = b;
        return 0;
}

static int make_lock_dir(RuntimeScope scope) {
        int r;

        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(scope, "systemd", &p);
        if (r < 0)
                return r;

        _cleanup_close_ int pfd = open_mkdir_at(AT_FDCWD, p, O_CLOEXEC, 0755);
        if (pfd < 0)
                return pfd;

        _cleanup_close_ int nfd = open_mkdir_at(pfd, "nspawn", O_CLOEXEC, 0755);
        if (nfd < 0)
                return nfd;

        r = RET_NERRNO(mkdirat(nfd, "locks", 0700));
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int image_path_lock(
                RuntimeScope scope,
                const char *path,
                int operation,
                LockFile *ret_global,
                LockFile *ret_local) {

        _cleanup_free_ char *p = NULL;
        LockFile t = LOCK_FILE_INIT;
        struct stat st;
        bool exclusive;
        int r;

        assert(path);
        assert(ret_local);

        /* Locks an image path. This actually creates two locks: one "local" one, next to the image path
         * itself, which might be shared via NFS. And another "global" one, in /run/, that uses the
         * device/inode number. This has the benefit that we can even lock a tree that is a mount point,
         * correctly. */

        if (!path_is_absolute(path))
                return -EINVAL;

        switch (operation & (LOCK_SH|LOCK_EX)) {
        case LOCK_SH:
                exclusive = false;
                break;
        case LOCK_EX:
                exclusive = true;
                break;
        default:
                return -EINVAL;
        }

        if (getenv_bool("SYSTEMD_NSPAWN_LOCK") == 0) {
                *ret_local = LOCK_FILE_INIT;
                if (ret_global)
                        *ret_global = LOCK_FILE_INIT;
                return 0;
        }

        /* Prohibit taking exclusive locks on the host image. We can't allow this, since we ourselves are
         * running off it after all, and we don't want any images to manipulate the host image. We make an
         * exception for shared locks however: we allow those (and make them NOPs since there's no point in
         * taking them if there can't be exclusive locks). Strictly speaking these are questionable as well,
         * since it means changes made to the host might propagate to the container as they happen (and a
         * shared lock kinda suggests that no changes happen at all while it is in place), but it's too
         * useful not to allow read-only containers off the host root, hence let's support this, and trust
         * the user to do the right thing with this. */
        if (path_equal(path, "/")) {
                if (exclusive)
                        return -EBUSY;

                *ret_local = LOCK_FILE_INIT;
                if (ret_global)
                        *ret_global = LOCK_FILE_INIT;
                return 0;
        }

        if (ret_global) {
                if (stat(path, &st) < 0)
                        log_debug_errno(errno, "Failed to stat() image '%s', not locking image: %m", path);
                else {
                        r = runtime_directory_generic(scope, "systemd/nspawn/locks/", &p);
                        if (r < 0)
                                return r;

                        if (S_ISBLK(st.st_mode))
                                r = strextendf(&p, "block-" DEVNUM_FORMAT_STR, DEVNUM_FORMAT_VAL(st.st_rdev));
                        else if (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))
                                r = strextendf(&p, "inode-%" PRIu64 ":%" PRIu64, (uint64_t) st.st_dev, (uint64_t) st.st_ino);
                        else
                                return -ENOTTY;
                        if (r < 0)
                                return r;
                }
        }

        /* For block devices we don't need the "local" lock, as the major/minor lock above should be
         * sufficient, since block devices are host local anyway. */
        if (!path_startswith(path, "/dev/")) {
                r = make_lock_file_for(path, operation, &t);
                if (r < 0) {
                        if (exclusive || r != -EROFS)
                                return r;

                        log_debug_errno(r, "Failed to create shared lock for '%s', ignoring: %m", path);
                }
        }

        if (p) {
                (void) make_lock_dir(scope);

                r = make_lock_file(p, operation, ret_global);
                if (r < 0) {
                        release_lock_file(&t);
                        return r;
                }
        } else if (ret_global)
                *ret_global = LOCK_FILE_INIT;

        *ret_local = t;
        return 0;
}

int image_set_limit(Image *i, uint64_t referenced_max) {
        int r;

        assert(i);

        if (image_is_vendor(i) || image_is_host(i))
                return -EROFS;

        if (i->type != IMAGE_SUBVOLUME)
                return -EOPNOTSUPP;

        /* We set the quota both for the subvolume as well as for the
         * subtree. The latter is mostly for historical reasons, since
         * we didn't use to have a concept of subtree quota, and hence
         * only modified the subvolume quota. */

        (void) btrfs_qgroup_set_limit(i->path, 0, referenced_max);
        (void) btrfs_subvol_auto_qgroup(i->path, 0, true);
        r = btrfs_subvol_set_subtree_quota_limit(i->path, 0, referenced_max);
        if (r < 0)
                return r;

        (void) image_update_quota(i, -EBADF);
        return 0;
}

int image_set_pool_limit(RuntimeScope scope, ImageClass class, uint64_t referenced_max) {
        int r;

        assert(scope >= 0 && scope < _RUNTIME_SCOPE_MAX);
        assert(class >= 0 && class < _IMAGE_CLASS_MAX);

        _cleanup_free_ char *pool = NULL;
        r = get_pool_directory(scope, class, /* fname= */ NULL, /* suffix= */ NULL, &pool);
        if (r < 0)
                return r;

        r = btrfs_qgroup_set_limit(pool, /* qgroupid= */ 0, referenced_max);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return r;
        if (r < 0)
                log_debug_errno(r, "Failed to set limit on btrfs quota group for '%s', ignoring: %m", pool);

        r = btrfs_subvol_set_subtree_quota_limit(pool, /* subvol_id= */ 0, referenced_max);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return r;
        if (r < 0)
                return log_debug_errno(r, "Failed to set subtree quota limit for '%s': %m", pool);

        return 0;
}

int image_get_pool_path(RuntimeScope scope, ImageClass class, char **ret) {
        assert(scope >= 0 && scope < _RUNTIME_SCOPE_MAX);
        assert(class >= 0 && class < _IMAGE_CLASS_MAX);
        assert(ret);

        return get_pool_directory(scope, class, /* fname= */ NULL, /* suffix= */ NULL, ret);
}

int image_get_pool_usage(RuntimeScope scope, ImageClass class, uint64_t *ret) {
        int r;

        assert(scope >= 0 && scope < _RUNTIME_SCOPE_MAX);
        assert(class >= 0 && class < _IMAGE_CLASS_MAX);
        assert(ret);

        _cleanup_free_ char *pool = NULL;
        r = get_pool_directory(scope, class, /* fname= */ NULL, /* suffix= */ NULL, &pool);
        if (r < 0)
                return r;

        _cleanup_close_ int fd = open(pool, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        BtrfsQuotaInfo q;
        r = btrfs_subvol_get_subtree_quota_fd(fd, /* subvol_id= */ 0, &q);
        if (r < 0)
                return r;

        *ret = q.referenced;
        return 0;
}

int image_get_pool_limit(RuntimeScope scope, ImageClass class, uint64_t *ret) {
        int r;

        assert(scope >= 0 && scope < _RUNTIME_SCOPE_MAX);
        assert(class >= 0 && class < _IMAGE_CLASS_MAX);
        assert(ret);

        _cleanup_free_ char *pool = NULL;
        r = get_pool_directory(scope, class, /* fname= */ NULL, /* suffix= */ NULL, &pool);
        if (r < 0)
                return r;

        _cleanup_close_ int fd = open(pool, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return -errno;

        BtrfsQuotaInfo q;
        r = btrfs_subvol_get_subtree_quota_fd(fd, /* subvol_id= */ 0, &q);
        if (r < 0)
                return r;

        *ret = q.referenced_max;
        return 0;
}

static int check_btrfs(const char *path) {
        struct statfs sfs;
        int r;

        if (statfs(path, &sfs) < 0) {
                if (errno != ENOENT)
                        return -errno;

                _cleanup_free_ char *parent = NULL;
                r = path_extract_directory(path, &parent);
                if (r < 0)
                        return r;

                if (statfs(parent, &sfs) < 0)
                        return -errno;
        }

        return F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
}

int image_setup_pool(RuntimeScope scope, ImageClass class, bool use_btrfs_subvol, bool use_btrfs_quota) {
        int r;

        assert(class >= 0 && class < _IMAGE_CLASS_MAX);

        _cleanup_free_ char *pool = NULL;
        r = image_get_pool_path(scope, class, &pool);
        if (r < 0)
                return r;

        r = check_btrfs(pool);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        if (!use_btrfs_subvol)
                return 0;

        (void) btrfs_subvol_make_label(pool);

        if (!use_btrfs_quota)
                return 0;

        r = btrfs_quota_enable(pool, /* b= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to enable quota for %s, ignoring: %m", pool);

        r = btrfs_subvol_auto_qgroup(pool, /* subvol_id= */ 0, /* create_intermediary_qgroup= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to set up default quota hierarchy for %s, ignoring: %m", pool);

        return 0;
}

int image_read_metadata(Image *i, const char *root, const ImagePolicy *image_policy, RuntimeScope scope) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        int r;

        assert(i);

        r = image_path_lock(scope, i->path, LOCK_SH|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:
        case IMAGE_DIRECTORY: {
                _cleanup_strv_free_ char **machine_info = NULL, **os_release = NULL, **sysext_release = NULL, **confext_release = NULL;
                _cleanup_free_ char *hostname = NULL, *path = NULL;
                sd_id128_t machine_id = SD_ID128_NULL;

                if (i->class == IMAGE_SYSEXT) {
                        r = extension_has_forbidden_content(i->path);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                                       "Conflicting content found in image %s, refusing.",
                                                       i->name);
                }

                r = chase("/etc/hostname", i->path, CHASE_PREFIX_ROOT|CHASE_TRAIL_SLASH, &path, NULL);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to chase /etc/hostname in image %s: %m", i->name);
                else if (r >= 0) {
                        r = read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read /etc/hostname of image %s: %m", i->name);
                }

                path = mfree(path);

                r = id128_get_machine(i->path, &machine_id);
                if (r < 0)
                        log_debug_errno(r, "Failed to read machine ID in image %s, ignoring: %m", i->name);

                r = chase("/etc/machine-info", i->path, CHASE_PREFIX_ROOT|CHASE_TRAIL_SLASH, &path, NULL);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to chase /etc/machine-info in image %s: %m", i->name);
                else if (r >= 0) {
                        r = load_env_file_pairs(NULL, path, &machine_info);
                        if (r < 0)
                                log_debug_errno(r, "Failed to parse machine-info data of %s: %m", i->name);
                }

                r = load_os_release_pairs(i->path, &os_release);
                if (r < 0)
                        log_debug_errno(r, "Failed to read os-release in image, ignoring: %m");

                r = load_extension_release_pairs(i->path, IMAGE_SYSEXT, i->name, /* relax_extension_release_check= */ false, &sysext_release);
                if (r < 0)
                        log_debug_errno(r, "Failed to read sysext-release in image, ignoring: %m");

                r = load_extension_release_pairs(i->path, IMAGE_CONFEXT, i->name, /* relax_extension_release_check= */ false, &confext_release);
                if (r < 0)
                        log_debug_errno(r, "Failed to read confext-release in image, ignoring: %m");

                free_and_replace(i->hostname, hostname);
                i->machine_id = machine_id;
                strv_free_and_replace(i->machine_info, machine_info);
                strv_free_and_replace(i->os_release, os_release);
                strv_free_and_replace(i->sysext_release, sysext_release);
                strv_free_and_replace(i->confext_release, confext_release);
                break;
        }

        case IMAGE_RAW:
        case IMAGE_BLOCK: {
                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
                _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
                DissectImageFlags flags =
                        DISSECT_IMAGE_GENERIC_ROOT |
                        DISSECT_IMAGE_REQUIRE_ROOT |
                        DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_READ_ONLY |
                        DISSECT_IMAGE_USR_NO_ROOT |
                        DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                        DISSECT_IMAGE_PIN_PARTITION_DEVICES |
                        DISSECT_IMAGE_VALIDATE_OS |
                        DISSECT_IMAGE_VALIDATE_OS_EXT |
                        DISSECT_IMAGE_ALLOW_USERSPACE_VERITY;

                r = loop_device_make_by_path(
                                i->path,
                                O_RDONLY,
                                /* sector_size= */ UINT32_MAX,
                                LO_FLAGS_PARTSCAN,
                                LOCK_SH,
                                &d);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create loopback device of '%s': %m", i->path);

                r = dissect_loop_device(
                                d,
                                &verity,
                                /* mount_options= */ NULL,
                                image_policy,
                                /* image_filter= */ NULL,
                                flags,
                                &m);
                if (r < 0)
                        return log_debug_errno(r, "Failed to dissect image '%s': %m", i->path);

                r = dissected_image_load_verity_sig_partition(
                                m,
                                d->fd,
                                &verity);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load Verity signature partition of '%s': %m", i->path);

                r = dissected_image_guess_verity_roothash(
                                m,
                                &verity);
                if (r < 0)
                        return log_debug_errno(r, "Failed to guess Verity root hash of '%s': %m", i->path);

                r = dissected_image_decrypt(
                                m,
                                root,
                                /* passphrase= */ NULL,
                                &verity,
                                image_policy,
                                flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to decrypt image '%s': %m", i->path);

                /* Do not use the image name derived from the backing file of the loop device */
                r = free_and_strdup(&m->image_name, i->name);
                if (r < 0)
                        return r;

                r = dissected_image_acquire_metadata(
                                m,
                                /* userns_fd= */ -EBADF,
                                flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire metadata from image '%s': %m", i->path);

                free_and_replace(i->hostname, m->hostname);
                i->machine_id = m->machine_id;
                strv_free_and_replace(i->machine_info, m->machine_info);
                strv_free_and_replace(i->os_release, m->os_release);
                strv_free_and_replace(i->sysext_release, m->sysext_release);
                strv_free_and_replace(i->confext_release, m->confext_release);
                break;
        }

        default:
                return -EOPNOTSUPP;
        }

        i->metadata_valid = true;

        return 0;
}

int image_name_lock(
                RuntimeScope scope,
                const char *name,
                int operation,
                LockFile *ret) {

        int r;

        assert(name);
        assert(ret);

        /* Locks an image name, regardless of the precise path used. */

        if (streq(name, ".host"))
                return -EBUSY;

        if (!image_name_is_valid(name))
                return -EINVAL;

        if (getenv_bool("SYSTEMD_NSPAWN_LOCK") == 0) {
                *ret = (LockFile) LOCK_FILE_INIT;
                return 0;
        }

        (void) make_lock_dir(scope);

        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(scope, "systemd/nspawn/locks/name-", &p);
        if (r < 0)
                return r;

        if (!strextend(&p, name))
                return -ENOMEM;

        return make_lock_file(p, operation, ret);
}

bool image_in_search_path(
                RuntimeScope scope,
                ImageClass class,
                const char *root,
                const char *image) {

        int r;

        assert(scope < _RUNTIME_SCOPE_MAX && scope != RUNTIME_SCOPE_GLOBAL);
        assert(class >= 0);
        assert(class < _IMAGE_CLASS_MAX);
        assert(image);

        _cleanup_strv_free_ char **search = NULL;
        r = pick_image_search_path(scope, class, root, &search);
        if (r < 0)
                return r;

        STRV_FOREACH(path, search) {
                const char *p, *q;
                size_t k;

                if (!empty_or_root(root)) {
                        q = path_startswith(*path, root);
                        if (!q)
                                continue;
                } else
                        q = *path;

                p = path_startswith(q, *path);
                if (!p)
                        continue;

                /* Make sure there's a filename following */
                k = strcspn(p, "/");
                if (k == 0)
                        continue;

                p += k;

                /* Accept trailing slashes */
                if (p[strspn(p, "/")] == 0)
                        return true;
        }

        return false;
}

bool image_is_vendor(const struct Image *i) {
        assert(i);

        return i->path && path_startswith(i->path, "/usr");
}

bool image_is_host(const struct Image *i) {
        assert(i);

        if (i->name && streq(i->name, ".host"))
                return true;

        if (i->path && path_equal(i->path, "/"))
                return true;

        return false;
}

int image_to_json(const struct Image *img, sd_json_variant **ret) {
        assert(img);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("Type", image_type_to_string(img->type)),
                        SD_JSON_BUILD_PAIR_STRING("Class", image_class_to_string(img->class)),
                        SD_JSON_BUILD_PAIR_STRING("Name", img->name),
                        SD_JSON_BUILD_PAIR_CONDITION(!!img->path, "Path", SD_JSON_BUILD_STRING(img->path)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ReadOnly", image_is_read_only(img)),
                        SD_JSON_BUILD_PAIR_CONDITION(img->crtime != 0, "CreationTimestamp", SD_JSON_BUILD_UNSIGNED(img->crtime)),
                        SD_JSON_BUILD_PAIR_CONDITION(img->mtime != 0, "ModificationTimestamp", SD_JSON_BUILD_UNSIGNED(img->mtime)),
                        SD_JSON_BUILD_PAIR_CONDITION(img->usage != UINT64_MAX, "Usage", SD_JSON_BUILD_UNSIGNED(img->usage)),
                        SD_JSON_BUILD_PAIR_CONDITION(img->usage_exclusive != UINT64_MAX, "UsageExclusive", SD_JSON_BUILD_UNSIGNED(img->usage_exclusive)),
                        SD_JSON_BUILD_PAIR_CONDITION(img->limit != UINT64_MAX, "Limit", SD_JSON_BUILD_UNSIGNED(img->limit)),
                        SD_JSON_BUILD_PAIR_CONDITION(img->limit_exclusive != UINT64_MAX, "LimitExclusive", SD_JSON_BUILD_UNSIGNED(img->limit_exclusive)));
}

static const char* const image_type_table[_IMAGE_TYPE_MAX] = {
        [IMAGE_DIRECTORY] = "directory",
        [IMAGE_SUBVOLUME] = "subvolume",
        [IMAGE_RAW]       = "raw",
        [IMAGE_BLOCK]     = "block",
        [IMAGE_MSTACK]    = "mstack",
};

DEFINE_STRING_TABLE_LOOKUP(image_type, ImageType);

int image_root_pick(
                RuntimeScope scope,
                ImageClass c,
                bool runtime,
                char **ret) {

        int r;

        assert(scope >= 0);
        assert(scope < _RUNTIME_SCOPE_MAX);
        assert(c >= 0);
        assert(c < _IMAGE_CLASS_MAX);
        assert(ret);

        /* Picks the primary target directory for downloads, depending on invocation contexts */

        _cleanup_free_ char *s = NULL;
        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM: {
                s = strdup(runtime ? image_root_runtime_to_string(c) : image_root_to_string(c));
                if (!s)
                        return -ENOMEM;

                break;
        }

        case RUNTIME_SCOPE_USER:
                r = sd_path_lookup(runtime ? SD_PATH_USER_RUNTIME : SD_PATH_USER_STATE_PRIVATE, "machines", &s);
                if (r < 0)
                        return r;

                break;

        default:
                return -EOPNOTSUPP;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

BUS_DEFINE_PROPERTY_GET(bus_property_get_image_is_read_only, "b", Image, (int) image_is_read_only);
