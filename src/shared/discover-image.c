/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "chase.h"
#include "chattr-util.h"
#include "copy.h"
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
#include "initrd-util.h"
#include "lock-util.h"
#include "log.h"
#include "loop-util.h"
#include "macro.h"
#include "mkdir.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "utf8.h"
#include "vpick.h"
#include "xattr-util.h"

static const char* const image_search_path[_IMAGE_CLASS_MAX] = {
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

/* Inside the initrd, use a slightly different set of search path (i.e. include .extra/sysext/ and
 * .extra/confext/ in extension search dir) */
static const char* const image_search_path_initrd[_IMAGE_CLASS_MAX] = {
        /* (entries that aren't listed here will get the same search path as for the non initrd-case) */

        [IMAGE_SYSEXT] =    "/etc/extensions\0"            /* only place symlinks here */
                            "/run/extensions\0"            /* and here too */
                            "/var/lib/extensions\0"        /* the main place for images */
                            "/.extra/sysext\0",            /* put sysext picked up by systemd-stub last, since not trusted */

        [IMAGE_CONFEXT] =   "/run/confexts\0"              /* only place symlinks here */
                            "/var/lib/confexts\0"          /* the main place for images */
                            "/usr/local/lib/confexts\0"
                            "/.extra/confext\0",           /* put confext picked up by systemd-stub last, since not trusted */
};

static const char* image_class_suffix_table[_IMAGE_CLASS_MAX] = {
        [IMAGE_SYSEXT]  = ".sysext",
        [IMAGE_CONFEXT] = ".confext",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(image_class_suffix, ImageClass);

static Image *image_free(Image *i) {
        assert(i);

        free(i->name);
        free(i->path);

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

static char **image_settings_path(Image *image) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *fn = NULL;
        size_t i = 0;
        int r;

        assert(image);

        l = new0(char*, 4);
        if (!l)
                return NULL;

        fn = strjoin(image->name, ".nspawn");
        if (!fn)
                return NULL;

        FOREACH_STRING(s, "/etc/systemd/nspawn", "/run/systemd/nspawn") {
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

static int image_roothash_path(Image *image, char **ret) {
        _cleanup_free_ char *fn = NULL;

        assert(image);

        fn = strjoin(image->name, ".roothash");
        if (!fn)
                return -ENOMEM;

        return file_in_same_dir(image->path, fn, ret);
}

static int image_new(
                ImageType t,
                ImageClass c,
                const char *pretty,
                const char *path,
                const char *filename,
                bool read_only,
                usec_t crtime,
                usec_t mtime,
                Image **ret) {

        _cleanup_(image_unrefp) Image *i = NULL;

        assert(t >= 0);
        assert(t < _IMAGE_TYPE_MAX);
        assert(pretty);
        assert(filename);
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
                .usage = UINT64_MAX,
                .usage_exclusive = UINT64_MAX,
                .limit = UINT64_MAX,
                .limit_exclusive = UINT64_MAX,
        };

        i->name = strdup(pretty);
        if (!i->name)
                return -ENOMEM;

        i->path = path_join(path, filename);
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

static int image_make(
                ImageClass c,
                const char *pretty,
                int dfd,
                const char *path,
                const char *filename,
                const struct stat *st,
                Image **ret) {

        _cleanup_free_ char *pretty_buffer = NULL, *parent = NULL;
        struct stat stbuf;
        bool read_only;
        int r;

        assert(dfd >= 0 || dfd == AT_FDCWD);
        assert(path || dfd == AT_FDCWD);
        assert(filename);

        /* We explicitly *do* follow symlinks here, since we want to allow symlinking trees, raw files and block
         * devices into /var/lib/machines/, and treat them normally.
         *
         * This function returns -ENOENT if we can't find the image after all, and -EMEDIUMTYPE if it's not a file we
         * recognize. */

        if (!st) {
                if (fstatat(dfd, filename, &stbuf, 0) < 0)
                        return -errno;

                st = &stbuf;
        }

        if (!path) {
                if (dfd == AT_FDCWD)
                        (void) safe_getcwd(&parent);
                else
                        (void) fd_get_path(dfd, &parent);
        }

        read_only =
                (path && path_startswith(path, "/usr")) ||
                (faccessat(dfd, filename, W_OK, AT_EACCESS) < 0 && errno == EROFS);

        if (S_ISDIR(st->st_mode)) {
                _cleanup_close_ int fd = -EBADF;
                unsigned file_attr = 0;
                usec_t crtime = 0;

                if (!ret)
                        return 0;

                if (!pretty) {
                        r = extract_image_basename(
                                        filename,
                                        image_class_suffix_to_string(c),
                                        /* format_suffix= */ NULL,
                                        &pretty_buffer,
                                        /* ret_suffix= */ NULL);
                        if (r < 0)
                                return r;

                        pretty = pretty_buffer;
                }

                fd = openat(dfd, filename, O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                if (fd < 0)
                        return -errno;

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
                                              filename,
                                              info.read_only || read_only,
                                              info.otime,
                                              0,
                                              ret);
                                if (r < 0)
                                        return r;

                                if (btrfs_quota_scan_ongoing(fd) == 0) {
                                        BtrfsQuotaInfo quota;

                                        r = btrfs_subvol_get_subtree_quota_fd(fd, 0, &quota);
                                        if (r >= 0) {
                                                (*ret)->usage = quota.referenced;
                                                (*ret)->usage_exclusive = quota.exclusive;

                                                (*ret)->limit = quota.referenced_max;
                                                (*ret)->limit_exclusive = quota.exclusive_max;
                                        }
                                }

                                return 0;
                        }
                }

                /* Get directory creation time (not available everywhere, but that's OK */
                (void) fd_getcrtime(fd, &crtime);

                /* If the IMMUTABLE bit is set, we consider the directory read-only. Since the ioctl is not
                 * supported everywhere we ignore failures. */
                (void) read_attr_fd(fd, &file_attr);

                /* It's just a normal directory. */
                r = image_new(IMAGE_DIRECTORY,
                              c,
                              pretty,
                              path,
                              filename,
                              read_only || (file_attr & FS_IMMUTABLE_FL),
                              crtime,
                              0, /* we don't use mtime of stat() here, since it's not the time of last change of the tree, but only of the top-level dir */
                              ret);
                if (r < 0)
                        return r;

                return 0;

        } else if (S_ISREG(st->st_mode) && endswith(filename, ".raw")) {
                usec_t crtime = 0;

                /* It's a RAW disk image */

                if (!ret)
                        return 0;

                (void) fd_getcrtime_at(dfd, filename, AT_SYMLINK_FOLLOW, &crtime);

                if (!pretty) {
                        r = extract_image_basename(
                                        filename,
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
                              filename,
                              !(st->st_mode & 0222) || read_only,
                              crtime,
                              timespec_load(&st->st_mtim),
                              ret);
                if (r < 0)
                        return r;

                (*ret)->usage = (*ret)->usage_exclusive = st->st_blocks * 512;
                (*ret)->limit = (*ret)->limit_exclusive = st->st_size;

                return 0;

        } else if (S_ISBLK(st->st_mode)) {
                _cleanup_close_ int block_fd = -EBADF;
                uint64_t size = UINT64_MAX;

                /* A block device */

                if (!ret)
                        return 0;

                if (!pretty) {
                        r = extract_image_basename(
                                        filename,
                                        /* class_suffix= */ NULL,
                                        /* format_suffix= */ NULL,
                                        &pretty_buffer,
                                        /* ret_suffix= */ NULL);
                        if (r < 0)
                                return r;

                        pretty = pretty_buffer;
                }

                block_fd = openat(dfd, filename, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (block_fd < 0)
                        log_debug_errno(errno, "Failed to open block device %s/%s, ignoring: %m", path ?: strnull(parent), filename);
                else {
                        /* Refresh stat data after opening the node */
                        if (fstat(block_fd, &stbuf) < 0)
                                return -errno;
                        st = &stbuf;

                        if (!S_ISBLK(st->st_mode)) /* Verify that what we opened is actually what we think it is */
                                return -ENOTTY;

                        if (!read_only) {
                                int state = 0;

                                if (ioctl(block_fd, BLKROGET, &state) < 0)
                                        log_debug_errno(errno, "Failed to issue BLKROGET on device %s/%s, ignoring: %m", path ?: strnull(parent), filename);
                                else if (state)
                                        read_only = true;
                        }

                        r = blockdev_get_device_size(block_fd, &size);
                        if (r < 0)
                                log_debug_errno(r, "Failed to issue BLKGETSIZE64 on device %s/%s, ignoring: %m", path ?: strnull(parent), filename);

                        block_fd = safe_close(block_fd);
                }

                r = image_new(IMAGE_BLOCK,
                              c,
                              pretty,
                              path,
                              filename,
                              !(st->st_mode & 0222) || read_only,
                              0,
                              0,
                              ret);
                if (r < 0)
                        return r;

                if (!IN_SET(size, 0, UINT64_MAX))
                        (*ret)->usage = (*ret)->usage_exclusive = (*ret)->limit = (*ret)->limit_exclusive = size;

                return 0;
        }

        return -EMEDIUMTYPE;
}

static const char *pick_image_search_path(ImageClass class) {
        if (class < 0 || class >= _IMAGE_CLASS_MAX)
                return NULL;

        /* Use the initrd search path if there is one, otherwise use the common one */
        return in_initrd() && image_search_path_initrd[class] ? image_search_path_initrd[class] : image_search_path[class];
}

static char **make_possible_filenames(ImageClass class, const char *image_name) {
        _cleanup_strv_free_ char **l = NULL;

        assert(image_name);

        FOREACH_STRING(v_suffix, "", ".v")
                FOREACH_STRING(format_suffix, "", ".raw") {
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

int image_find(ImageClass class,
               const char *name,
               const char *root,
               Image **ret) {

        int r;

        assert(class >= 0);
        assert(class < _IMAGE_CLASS_MAX);
        assert(name);

        /* There are no images with invalid names */
        if (!image_name_is_valid(name))
                return -ENOENT;

        _cleanup_strv_free_ char **names = make_possible_filenames(class, name);
        if (!names)
                return -ENOMEM;

        NULSTR_FOREACH(path, pick_image_search_path(class)) {
                _cleanup_free_ char *resolved = NULL;
                _cleanup_closedir_ DIR *d = NULL;
                struct stat st;
                int flags;

                r = chase_and_opendir(path, root, CHASE_PREFIX_ROOT, &resolved, &d);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                /* As mentioned above, we follow symlinks on this fstatat(), because we want to permit people
                 * to symlink block devices into the search path. (For now, we disable that when operating
                 * relative to some root directory.) */
                flags = root ? AT_SYMLINK_NOFOLLOW : 0;

                STRV_FOREACH(n, names) {
                        _cleanup_free_ char *fname_buf = NULL;
                        const char *fname = *n;

                        if (fstatat(dirfd(d), fname, &st, flags) < 0) {
                                if (errno != ENOENT)
                                        return -errno;

                                continue; /* Vanished while we were looking at it */
                        }

                        if (endswith(fname, ".raw")) {
                                if (!S_ISREG(st.st_mode)) {
                                        log_debug("Ignoring non-regular file '%s' with .raw suffix.", fname);
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

                                _cleanup_free_ char *vp = path_join(resolved, fname);
                                if (!vp)
                                        return -ENOMEM;

                                PickFilter filter = {
                                        .type_mask = endswith(suffix, ".raw") ? (UINT32_C(1) << DT_REG) | (UINT32_C(1) << DT_BLK) : (UINT32_C(1) << DT_DIR),
                                        .basename = name,
                                        .architecture = _ARCHITECTURE_INVALID,
                                        .suffix = suffix,
                                };

                                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                                r = path_pick(root,
                                              /* toplevel_fd= */ AT_FDCWD,
                                              vp,
                                              &filter,
                                              PICK_ARCHITECTURE|PICK_TRIES,
                                              &result);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to pick versioned image on '%s', skipping: %m", vp);
                                        continue;
                                }
                                if (!result.path) {
                                        log_debug("Found versioned directory '%s', without matching entry, skipping: %m", vp);
                                        continue;
                                }

                                /* Refresh the stat data for the discovered target */
                                st = result.st;

                                _cleanup_free_ char *bn = NULL;
                                r = path_extract_filename(result.path, &bn);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to extract basename of image path '%s', skipping: %m", result.path);
                                        continue;
                                }

                                fname_buf = path_join(fname, bn);
                                if (!fname_buf)
                                        return log_oom();

                                fname = fname_buf;

                        } else if (!S_ISDIR(st.st_mode) && !S_ISBLK(st.st_mode)) {
                                log_debug("Ignoring non-directory and non-block device file '%s' without suffix.", fname);
                                continue;
                        }

                        r = image_make(class, name, dirfd(d), resolved, fname, &st, ret);
                        if (IN_SET(r, -ENOENT, -EMEDIUMTYPE))
                                continue;
                        if (r < 0)
                                return r;

                        if (ret)
                                (*ret)->discoverable = true;

                        return 1;
                }
        }

        if (class == IMAGE_MACHINE && streq(name, ".host")) {
                r = image_make(class, ".host", AT_FDCWD, NULL, empty_to_root(root), NULL, ret);
                if (r < 0)
                        return r;

                if (ret)
                        (*ret)->discoverable = true;

                return 1;
        }

        return -ENOENT;
};

int image_from_path(const char *path, Image **ret) {

        /* Note that we don't set the 'discoverable' field of the returned object, because we don't check here whether
         * the image is in the image search path. And if it is we don't know if the path we used is actually not
         * overridden by another, different image earlier in the search path */

        if (path_equal(path, "/"))
                return image_make(IMAGE_MACHINE, ".host", AT_FDCWD, NULL, "/", NULL, ret);

        return image_make(_IMAGE_CLASS_INVALID, NULL, AT_FDCWD, NULL, path, NULL, ret);
}

int image_find_harder(ImageClass class, const char *name_or_path, const char *root, Image **ret) {
        if (image_name_is_valid(name_or_path))
                return image_find(class, name_or_path, root, ret);

        return image_from_path(name_or_path, ret);
}

int image_discover(
                ImageClass class,
                const char *root,
                Hashmap *h) {

        int r;

        assert(class >= 0);
        assert(class < _IMAGE_CLASS_MAX);
        assert(h);

        NULSTR_FOREACH(path, pick_image_search_path(class)) {
                _cleanup_free_ char *resolved = NULL;
                _cleanup_closedir_ DIR *d = NULL;

                r = chase_and_opendir(path, root, CHASE_PREFIX_ROOT, &resolved, &d);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                FOREACH_DIRENT_ALL(de, d, return -errno) {
                        _cleanup_free_ char *pretty = NULL, *fname_buf = NULL;
                        _cleanup_(image_unrefp) Image *image = NULL;
                        const char *fname = de->d_name;
                        struct stat st;
                        int flags;

                        if (dot_or_dot_dot(fname))
                                continue;

                        /* As mentioned above, we follow symlinks on this fstatat(), because we want to
                         * permit people to symlink block devices into the search path. */
                        flags = root ? AT_SYMLINK_NOFOLLOW : 0;
                        if (fstatat(dirfd(d), fname, &st, flags) < 0) {
                                if (errno == ENOENT)
                                        continue;

                                return -errno;
                        }

                        if (S_ISREG(st.st_mode)) {
                                r = extract_image_basename(
                                                fname,
                                                image_class_suffix_to_string(class),
                                                STRV_MAKE(".raw"),
                                                &pretty,
                                                /* suffix= */ NULL);
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
                                                        STRV_MAKE(".raw", ""),
                                                        &pretty,
                                                        &suffix);
                                        if (r < 0) {
                                                log_debug_errno(r, "Skipping directory entry '%s', which doesn't look like a versioned image.", fname);
                                                continue;
                                        }

                                        _cleanup_free_ char *vp = path_join(resolved, fname);
                                        if (!vp)
                                                return -ENOMEM;

                                        PickFilter filter = {
                                                .type_mask = endswith(suffix, ".raw") ? (UINT32_C(1) << DT_REG) | (UINT32_C(1) << DT_BLK) : (UINT32_C(1) << DT_DIR),
                                                .basename = pretty,
                                                .architecture = _ARCHITECTURE_INVALID,
                                                .suffix = suffix,
                                        };

                                        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                                        r = path_pick(root,
                                                      /* toplevel_fd= */ AT_FDCWD,
                                                      vp,
                                                      &filter,
                                                      PICK_ARCHITECTURE|PICK_TRIES,
                                                      &result);
                                        if (r < 0) {
                                                log_debug_errno(r, "Failed to pick versioned image on '%s', skipping: %m", vp);
                                                continue;
                                        }
                                        if (!result.path) {
                                                log_debug("Found versioned directory '%s', without matching entry, skipping: %m", vp);
                                                continue;
                                        }

                                        /* Refresh the stat data for the discovered target */
                                        st = result.st;

                                        _cleanup_free_ char *bn = NULL;
                                        r = path_extract_filename(result.path, &bn);
                                        if (r < 0) {
                                                log_debug_errno(r, "Failed to extract basename of image path '%s', skipping: %m", result.path);
                                                continue;
                                        }

                                        fname_buf = path_join(fname, bn);
                                        if (!fname_buf)
                                                return log_oom();

                                        fname = fname_buf;
                                } else {
                                        r = extract_image_basename(
                                                        fname,
                                                        image_class_suffix_to_string(class),
                                                        /* format_suffix= */ NULL,
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
                                                /* ret_v_suffix= */ NULL);
                                if (r < 0) {
                                        log_debug_errno(r, "Skipping directory entry '%s', which doesn't look like an image.", fname);
                                        continue;
                                }
                        } else {
                                log_debug("Skipping directory entry '%s', which is neither regular file, directory nor block device.", fname);
                                continue;
                        }

                        if (hashmap_contains(h, pretty))
                                continue;

                        r = image_make(class, pretty, dirfd(d), resolved, fname, &st, &image);
                        if (IN_SET(r, -ENOENT, -EMEDIUMTYPE))
                                continue;
                        if (r < 0)
                                return r;

                        image->discoverable = true;

                        r = hashmap_put(h, image->name, image);
                        if (r < 0)
                                return r;

                        TAKE_PTR(image);
                }
        }

        if (class == IMAGE_MACHINE && !hashmap_contains(h, ".host")) {
                _cleanup_(image_unrefp) Image *image = NULL;

                r = image_make(IMAGE_MACHINE, ".host", AT_FDCWD, NULL, empty_to_root("/"), NULL, &image);
                if (r < 0)
                        return r;

                image->discoverable = true;

                r = hashmap_put(h, image->name, image);
                if (r < 0)
                        return r;

                image = NULL;
        }

        return 0;
}

int image_remove(Image *i) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **settings = NULL;
        _cleanup_free_ char *roothash = NULL;
        int r;

        assert(i);

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        settings = image_settings_path(i);
        if (!settings)
                return -ENOMEM;

        r = image_roothash_path(i, &roothash);
        if (r < 0)
                return r;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
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
                (void) chattr_path(i->path, 0, FS_IMMUTABLE_FL, NULL);
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

        if (unlink(roothash) < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to unlink %s, ignoring: %m", roothash);

        return 0;
}

static int rename_auxiliary_file(const char *path, const char *new_name, const char *suffix) {
        _cleanup_free_ char *fn = NULL, *rs = NULL;
        int r;

        fn = strjoin(new_name, suffix);
        if (!fn)
                return -ENOMEM;

        r = file_in_same_dir(path, fn, &rs);
        if (r < 0)
                return r;

        return rename_noreplace(AT_FDCWD, path, AT_FDCWD, rs);
}

int image_rename(Image *i, const char *new_name) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT, name_lock = LOCK_FILE_INIT;
        _cleanup_free_ char *new_path = NULL, *nn = NULL, *roothash = NULL;
        _cleanup_strv_free_ char **settings = NULL;
        unsigned file_attr = 0;
        int r;

        assert(i);

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        settings = image_settings_path(i);
        if (!settings)
                return -ENOMEM;

        r = image_roothash_path(i, &roothash);
        if (r < 0)
                return r;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
        if (r < 0)
                return r;

        /* Make sure nobody takes the new name, between the time we
         * checked it is currently unused in all search paths, and the
         * time we take possession of it */
        r = image_name_lock(new_name, LOCK_EX|LOCK_NB, &name_lock);
        if (r < 0)
                return r;

        r = image_find(IMAGE_MACHINE, new_name, NULL, NULL);
        if (r >= 0)
                return -EEXIST;
        if (r != -ENOENT)
                return r;

        switch (i->type) {

        case IMAGE_DIRECTORY:
                /* Turn of the immutable bit while we rename the image, so that we can rename it */
                (void) read_attr_path(i->path, &file_attr);

                if (file_attr & FS_IMMUTABLE_FL)
                        (void) chattr_path(i->path, 0, FS_IMMUTABLE_FL, NULL);

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
                (void) chattr_path(new_path, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL, NULL);

        free_and_replace(i->path, new_path);
        free_and_replace(i->name, nn);

        STRV_FOREACH(j, settings) {
                r = rename_auxiliary_file(*j, new_name, ".nspawn");
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to rename settings file %s, ignoring: %m", *j);
        }

        r = rename_auxiliary_file(roothash, new_name, ".roothash");
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to rename roothash file %s, ignoring: %m", roothash);

        return 0;
}

static int clone_auxiliary_file(const char *path, const char *new_name, const char *suffix) {
        _cleanup_free_ char *fn = NULL, *rs = NULL;
        int r;

        fn = strjoin(new_name, suffix);
        if (!fn)
                return -ENOMEM;

        r = file_in_same_dir(path, fn, &rs);
        if (r < 0)
                return r;

        return copy_file_atomic(path, rs, 0664, COPY_REFLINK);
}

int image_clone(Image *i, const char *new_name, bool read_only) {
        _cleanup_(release_lock_file) LockFile name_lock = LOCK_FILE_INIT;
        _cleanup_strv_free_ char **settings = NULL;
        _cleanup_free_ char *roothash = NULL;
        const char *new_path;
        int r;

        assert(i);

        if (!image_name_is_valid(new_name))
                return -EINVAL;

        settings = image_settings_path(i);
        if (!settings)
                return -ENOMEM;

        r = image_roothash_path(i, &roothash);
        if (r < 0)
                return r;

        /* Make sure nobody takes the new name, between the time we
         * checked it is currently unused in all search paths, and the
         * time we take possession of it */
        r = image_name_lock(new_name, LOCK_EX|LOCK_NB, &name_lock);
        if (r < 0)
                return r;

        r = image_find(IMAGE_MACHINE, new_name, NULL, NULL);
        if (r >= 0)
                return -EEXIST;
        if (r != -ENOENT)
                return r;

        switch (i->type) {

        case IMAGE_SUBVOLUME:
        case IMAGE_DIRECTORY:
                /* If we can we'll always try to create a new btrfs subvolume here, even if the source is a plain
                 * directory. */

                new_path = strjoina("/var/lib/machines/", new_name);

                r = btrfs_subvol_snapshot_at(AT_FDCWD, i->path, AT_FDCWD, new_path,
                                             (read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                             BTRFS_SNAPSHOT_FALLBACK_COPY |
                                             BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                             BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE |
                                             BTRFS_SNAPSHOT_RECURSIVE |
                                             BTRFS_SNAPSHOT_QUOTA);
                if (r >= 0)
                        /* Enable "subtree" quotas for the copy, if we didn't copy any quota from the source. */
                        (void) btrfs_subvol_auto_qgroup(new_path, 0, true);

                break;

        case IMAGE_RAW:
                new_path = strjoina("/var/lib/machines/", new_name, ".raw");

                r = copy_file_atomic_full(i->path, new_path, read_only ? 0444 : 0644, FS_NOCOW_FL, FS_NOCOW_FL,
                                          COPY_REFLINK|COPY_CRTIME, NULL, NULL);
                break;

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

        r = clone_auxiliary_file(roothash, new_name, ".roothash");
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to clone root hash file %s, ignoring: %m", roothash);

        return 0;
}

int image_read_only(Image *i, bool b) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        int r;

        assert(i);

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        /* Make sure we don't interfere with a running nspawn */
        r = image_path_lock(i->path, LOCK_EX|LOCK_NB, &global_lock, &local_lock);
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

                r = chattr_path(i->path, b ? FS_IMMUTABLE_FL : 0, FS_IMMUTABLE_FL, NULL);
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

        return 0;
}

int image_path_lock(const char *path, int operation, LockFile *global, LockFile *local) {
        _cleanup_free_ char *p = NULL;
        LockFile t = LOCK_FILE_INIT;
        struct stat st;
        bool exclusive;
        int r;

        assert(path);
        assert(global);
        assert(local);

        /* Locks an image path. This actually creates two locks: one "local" one, next to the image path
         * itself, which might be shared via NFS. And another "global" one, in /run, that uses the
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
                *local = *global = (LockFile) LOCK_FILE_INIT;
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

                *local = *global = (LockFile) LOCK_FILE_INIT;
                return 0;
        }

        if (stat(path, &st) >= 0) {
                if (S_ISBLK(st.st_mode))
                        r = asprintf(&p, "/run/systemd/nspawn/locks/block-%u:%u", major(st.st_rdev), minor(st.st_rdev));
                else if (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))
                        r = asprintf(&p, "/run/systemd/nspawn/locks/inode-%lu:%lu", (unsigned long) st.st_dev, (unsigned long) st.st_ino);
                else
                        return -ENOTTY;
                if (r < 0)
                        return -ENOMEM;
        }

        /* For block devices we don't need the "local" lock, as the major/minor lock above should be
         * sufficient, since block devices are host local anyway. */
        if (!path_startswith(path, "/dev/")) {
                r = make_lock_file_for(path, operation, &t);
                if (r < 0) {
                        if (!exclusive && r == -EROFS)
                                log_debug_errno(r, "Failed to create shared lock for '%s', ignoring: %m", path);
                        else
                                return r;
                }
        }

        if (p) {
                (void) mkdir_p("/run/systemd/nspawn", 0755);
                (void) mkdir("/run/systemd/nspawn/locks", 0700);

                r = make_lock_file(p, operation, global);
                if (r < 0) {
                        release_lock_file(&t);
                        return r;
                }
        } else
                *global = (LockFile) LOCK_FILE_INIT;

        *local = t;
        return 0;
}

int image_set_limit(Image *i, uint64_t referenced_max) {
        assert(i);

        if (IMAGE_IS_VENDOR(i) || IMAGE_IS_HOST(i))
                return -EROFS;

        if (i->type != IMAGE_SUBVOLUME)
                return -EOPNOTSUPP;

        /* We set the quota both for the subvolume as well as for the
         * subtree. The latter is mostly for historical reasons, since
         * we didn't use to have a concept of subtree quota, and hence
         * only modified the subvolume quota. */

        (void) btrfs_qgroup_set_limit(i->path, 0, referenced_max);
        (void) btrfs_subvol_auto_qgroup(i->path, 0, true);
        return btrfs_subvol_set_subtree_quota_limit(i->path, 0, referenced_max);
}

int image_read_metadata(Image *i, const ImagePolicy *image_policy) {
        _cleanup_(release_lock_file) LockFile global_lock = LOCK_FILE_INIT, local_lock = LOCK_FILE_INIT;
        int r;

        assert(i);

        r = image_path_lock(i->path, LOCK_SH|LOCK_NB, &global_lock, &local_lock);
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
                        r = read_etc_hostname(path, &hostname);
                        if (r < 0)
                                log_debug_errno(errno, "Failed to read /etc/hostname of image %s: %m", i->name);
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
                _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;

                r = loop_device_make_by_path(i->path, O_RDONLY, /* sector_size= */ UINT32_MAX, LO_FLAGS_PARTSCAN, LOCK_SH, &d);
                if (r < 0)
                        return r;

                r = dissect_loop_device(
                                d,
                                /* verity= */ NULL,
                                /* mount_options= */ NULL,
                                image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_READ_ONLY |
                                DISSECT_IMAGE_USR_NO_ROOT |
                                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                                DISSECT_IMAGE_PIN_PARTITION_DEVICES,
                                &m);
                if (r < 0)
                        return r;

                r = dissected_image_acquire_metadata(m,
                                                     DISSECT_IMAGE_VALIDATE_OS |
                                                     DISSECT_IMAGE_VALIDATE_OS_EXT);
                if (r < 0)
                        return r;

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

int image_name_lock(const char *name, int operation, LockFile *ret) {
        const char *p;

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

        (void) mkdir_p("/run/systemd/nspawn", 0755);
        (void) mkdir_p("/run/systemd/nspawn/locks", 0700);

        p = strjoina("/run/systemd/nspawn/locks/name-", name);
        return make_lock_file(p, operation, ret);
}

bool image_in_search_path(
                ImageClass class,
                const char *root,
                const char *image) {

        assert(image);

        NULSTR_FOREACH(path, pick_image_search_path(class)) {
                const char *p, *q;
                size_t k;

                if (!empty_or_root(root)) {
                        q = path_startswith(path, root);
                        if (!q)
                                continue;
                } else
                        q = path;

                p = path_startswith(q, path);
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

int image_to_json(const struct Image *img, JsonVariant **ret) {
        assert(img);

        return json_build(ret,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR_STRING("Type", image_type_to_string(img->type)),
                                          JSON_BUILD_PAIR_STRING("Class", image_class_to_string(img->class)),
                                          JSON_BUILD_PAIR_STRING("Name", img->name),
                                          JSON_BUILD_PAIR_CONDITION(img->path, "Path", JSON_BUILD_STRING(img->path)),
                                          JSON_BUILD_PAIR_BOOLEAN("ReadOnly", img->read_only),
                                          JSON_BUILD_PAIR_CONDITION(img->crtime != 0, "CreationTimestamp", JSON_BUILD_UNSIGNED(img->crtime)),
                                          JSON_BUILD_PAIR_CONDITION(img->mtime != 0, "ModificationTimestamp", JSON_BUILD_UNSIGNED(img->mtime)),
                                          JSON_BUILD_PAIR_CONDITION(img->usage != UINT64_MAX, "Usage", JSON_BUILD_UNSIGNED(img->usage)),
                                          JSON_BUILD_PAIR_CONDITION(img->usage_exclusive != UINT64_MAX, "UsageExclusive", JSON_BUILD_UNSIGNED(img->usage_exclusive)),
                                          JSON_BUILD_PAIR_CONDITION(img->limit != UINT64_MAX, "Limit", JSON_BUILD_UNSIGNED(img->limit)),
                                          JSON_BUILD_PAIR_CONDITION(img->limit_exclusive != UINT64_MAX, "LimitExclusive", JSON_BUILD_UNSIGNED(img->limit_exclusive))));
}

static const char* const image_type_table[_IMAGE_TYPE_MAX] = {
        [IMAGE_DIRECTORY] = "directory",
        [IMAGE_SUBVOLUME] = "subvolume",
        [IMAGE_RAW]       = "raw",
        [IMAGE_BLOCK]     = "block",
};

DEFINE_STRING_TABLE_LOOKUP(image_type, ImageType);
