/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "log.h"
#include "loop-util.h"
#include "macro.h"
#include "mstack.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "sort-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "vpick.h"

static void mstack_mount_done(MStackMount *m) {
        assert(m);

        m->where = mfree(m->where);
        m->what = mfree(m->what);
        m->what_fd = safe_close(m->what_fd);
        m->mount_fd = safe_close(m->mount_fd);
        m->sort_key = mfree(m->sort_key);
        m->dissected_image = dissected_image_unref(m->dissected_image);
}

static void mstack_done(MStack *mstack) {
        assert(mstack);

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                mstack_mount_done(m);

        mstack->mounts = mfree(mstack->mounts);
        mstack->n_mounts = 0;
        mstack->root_mount = NULL;
        mstack->has_tmpfs_root = mstack->has_overlayfs = false;
        mstack->path = mfree(mstack->path);
        safe_close(mstack->root_mount_fd);
        safe_close(mstack->usr_mount_fd);
}

MStack *mstack_free(MStack *mstack) {
        if (!mstack)
                return NULL;

        mstack_done(mstack);

        return mfree(mstack);
}

static int validate_prefix_name(const char *name, const char *prefix, char **ret_parameter) {
        _cleanup_free_ char *p = NULL;

        assert(name);
        assert(prefix);

        const char *a = startswith(name, prefix);
        if (!a)
                goto nomatch;

        p = strdup(a);
        if (!p)
                return -ENOMEM;

        if (isempty(p))
                goto nomatch;

        if (ret_parameter)
                *ret_parameter = TAKE_PTR(p);

        return true;

nomatch:
        if (ret_parameter)
                *ret_parameter = NULL;

        return false;
}

static MStackMount *mstack_find(MStack *mstack, MStackMountType t, const char *sort_key, const char *where) {
        assert(mstack);

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {

                if (t >= 0 && m->mount_type != t)
                        continue;

                if (sort_key && !streq_ptr(m->sort_key, sort_key))
                        continue;

                if (where && !path_equal(m->where, where))
                        continue;

                return m;
        }

        return NULL;
}

static int mstack_load_one(MStack *mstack, const char *dir, int dir_fd, const char *fname) {
        int r;

        assert(mstack);
        assert(dir_fd >= 0);
        assert(fname);

        _cleanup_close_ int what_fd = openat(dir_fd, fname, O_PATH|O_CLOEXEC);
        if (what_fd < 0)
                return log_error_errno(errno, "Failed to open %s/%s: %m", dir, fname);

        struct stat st;
        if (fstat(what_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s/%s: %m", dir, fname);

        ImageType image_type = _IMAGE_TYPE_INVALID;
        _cleanup_free_ char *what = NULL, *unsuffixed = NULL;
        if (S_ISDIR(st.st_mode)) {

                const char *dotv = endswith(fname, ".v");
                if (dotv) {
                        const char *dotrawv = endswith(fname, ".raw.v");

                        struct PickFilter filter = {
                                .type_mask = dotrawv ? (1U << DT_REG) : ((1U << DT_DIR) | (1U << DT_BLK)),
                                .suffix = dotrawv ? STRV_MAKE(".raw") : NULL,
                                .architecture = _ARCHITECTURE_INVALID,
                        };

                        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                        r = path_pick(dir, dir_fd, fname, &filter, PICK_ARCHITECTURE, &result);
                        if (r < 0)
                                return log_error_errno(r, "Failed to resolve '%s' directory: %m", fname);
                        if (r == 0)
                                return log_error_errno(r, "Found no suitable entry in '%s': %m", fname);

                        what = TAKE_PTR(result.path);
                        close_and_replace(what_fd, result.fd);
                        st = result.st;

                        unsuffixed = strndup(fname, (dotrawv ?: dotv) - fname);
                        if (!unsuffixed)
                                return log_oom();

                        image_type = S_ISDIR(st.st_mode) ? IMAGE_DIRECTORY :
                                     S_ISREG(st.st_mode) ? IMAGE_RAW :
                                     S_ISBLK(st.st_mode) ? IMAGE_BLOCK : _IMAGE_TYPE_INVALID;

                        assert(image_type >= 0);
                } else
                        image_type = IMAGE_DIRECTORY;

        } else if (S_ISREG(st.st_mode)) {
                const char *e = endswith(fname, ".raw");
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected suffix of '%s/%s', refusing.", dir, fname);

                unsuffixed = strndup(fname, e - fname);
                if (!unsuffixed)
                        return -ENOMEM;

                image_type = IMAGE_RAW;

        } else if (S_ISBLK(st.st_mode))
                image_type = IMAGE_BLOCK;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected inode type of '%s/%s', refusing.", dir, fname);

        if (!what) {
                what = strdup(fname);
                if (!what)
                        return -ENOMEM;
        }

        if (!unsuffixed) {
                unsuffixed = strdup(what);
                if (!unsuffixed)
                        return -ENOMEM;
        }

        if (!GREEDY_REALLOC(mstack->mounts, mstack->n_mounts+1))
                return -ENOMEM;

        MStackMount *m = mstack->mounts + mstack->n_mounts;

        _cleanup_free_ char *parameter = NULL;
        r = validate_prefix_name(unsuffixed, "layer@", &parameter);
        if (r < 0)
                return log_error_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
        if (r > 0) {
                /* Paranoia: let's refuse two layers that have the same sort key. Howe can that happen?
                 * People might have a .raw layer and one dir layer with the same name. Or one with .v and
                 * one without. */
                if (mstack_find(mstack, MSTACK_LAYER, parameter, /* where= */ NULL))
                        return log_error_errno(r, "Duplicate layer '%s', refusing", parameter);

                *m = (MStackMount) {
                        .mount_type = MSTACK_LAYER,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .sort_key = TAKE_PTR(parameter),
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                return 0;
        }

        if (streq(unsuffixed, "rw")) {
                if (mstack_find(mstack, MSTACK_RW, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_error_errno(r, "Duplicate rw entry, refusing");

                *m = (MStackMount) {
                        .mount_type = MSTACK_RW,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                return 0;
        }

        if (streq(unsuffixed, "work")) {
                if (mstack_find(mstack, MSTACK_WORK, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_error_errno(r, "Duplicate work entry, refusing");

                *m = (MStackMount) {
                        .mount_type = MSTACK_WORK,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                return 0;
        }

        MStackMountType bind_type = _MSTACK_MOUNT_TYPE_INVALID;
        r = validate_prefix_name(unsuffixed, "bind@", &parameter);
        if (r < 0)
                return log_error_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
        if (r > 0)
                bind_type = MSTACK_BIND;
        else {
                r = validate_prefix_name(unsuffixed, "robind@", &parameter);
                if (r < 0)
                        return log_error_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
                if (r > 0)
                        bind_type = MSTACK_ROBIND;
        }
        if (bind_type >= 0) {
                _cleanup_free_ char *where = NULL;
                r = unit_name_path_unescape(parameter, &where);
                if (r < 0)
                        return log_error_errno(r, "Cannot unescape path '%s' of '%s/%s'", parameter, dir, fname);

                if (mstack_find(mstack, MSTACK_BIND, /* sort_key= */ NULL, /* where= */ where) ||
                    mstack_find(mstack, MSTACK_ROBIND, /* sort_key= */ NULL, /* where= */ where))
                        return log_error_errno(r, "Duplicate bind entry, refusing");

                *m = (MStackMount) {
                        .mount_type = bind_type,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .where = TAKE_PTR(where),
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                return 0;
        }

        if (streq(unsuffixed, "root")) {
                if (mstack_find(mstack, MSTACK_ROOT, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_error_errno(r, "Duplicate root entry, refusing");

                *m = (MStackMount) {
                        .mount_type = MSTACK_ROOT,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unrecognized entry '%s/%s', refusing", dir, fname);
}

static int mount_compare_func(const MStackMount *a, const MStackMount *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->mount_type, b->mount_type);
        if (r != 0)
                return r;

        r = path_compare(a->where, b->where);
        if (r != 0)
                return r;

        r = strverscmp_improved(a->sort_key, b->sort_key);
        if (r != 0)
                return r;

        return 0;
}

static void mstack_remove(MStack *mstack, MStackMountType t) {
        assert(mstack);

        size_t z = 0;
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                if (m->mount_type == t)
                        mstack_mount_done(m);
                else
                        mstack->mounts[z++] = *m;
        }

        mstack->n_mounts = z;
}

static int mstack_normalize(MStack *mstack) {
        int r;

        assert(mstack);

        typesafe_qsort(mstack->mounts, mstack->n_mounts, mount_compare_func);

        size_t n_layers = 0;
        bool has_rw = false, has_work = false, has_root_bind = false, has_usr_bind = false, has_root = false;
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                switch (m->mount_type) {
                case MSTACK_LAYER:
                        n_layers++;
                        break;

                case MSTACK_RW:
                        assert(!has_rw);
                        has_rw = true;
                        break;

                case MSTACK_WORK:
                        assert(!has_work);
                        has_work = true;
                        break;

                case MSTACK_BIND:
                case MSTACK_ROBIND:
                        if (empty_or_root(m->where))
                                has_root_bind = true;
                        else if (path_equal(m->where, "/usr"))
                                has_usr_bind = true;
                        break;

                case MSTACK_ROOT:
                        assert(!has_root);
                        has_root = true;
                        break;

                default:
                        assert_not_reached();
                }
        }

        /* If the overlayfs stack is fully obstructed, kill it */
        if (has_root_bind || (has_root && has_usr_bind)) {
                mstack_remove(mstack, MSTACK_LAYER);
                mstack_remove(mstack, MSTACK_RW);

                n_layers = 0;
                has_rw = false;
        }

        /* Only a single read-only or read-write layer? Turn into bind mount! */
        if (n_layers + has_rw == 1) {
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                        if (m->mount_type == MSTACK_LAYER)
                                m->mount_type = MSTACK_ROBIND;
                        else if (m->mount_type == MSTACK_RW)
                                m->mount_type = MSTACK_BIND;
                        else
                                continue;

                        if (has_root) {
                                /* If there's a root dir, let's only bind mount the /usr/ subdir */
                                _cleanup_close_ int usr_fd = openat(m->what_fd, "usr", O_CLOEXEC|O_PATH|O_NOFOLLOW|O_DIRECTORY);
                                if (usr_fd < 0)
                                        return log_error_errno(errno, "Failed to open /usr/ subdir: %m");

                                _cleanup_free_ char *usr = path_join(m->what, "usr");
                                if (!usr)
                                        return log_oom();

                                close_and_replace(m->what_fd, usr_fd);
                                free_and_replace(m->what, usr);
                        } else {
                                r = free_and_strdup_warn(&m->where, "/");
                                if (r < 0)
                                        return r;
                        }
                }

                n_layers = 0;
                has_rw = false;
        }

        if (has_rw && !has_work)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No 'work' directory found but required.");

        /* If the root dir is overmounted, we can drop the original root */
        if (has_root_bind) {
                mstack_remove(mstack, MSTACK_ROOT);
                has_root = false;
        }

        /* After converting, let's sort things again */
        typesafe_qsort(mstack->mounts, mstack->n_mounts, mount_compare_func);

        /* Find root mount (unless it's the overlayfs stack) */
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if ((m->mount_type == MSTACK_ROOT) ||
                    (IN_SET(m->mount_type, MSTACK_BIND, MSTACK_ROBIND) && empty_or_root(m->where))) {
                        assert(!mstack->root_mount);
                        mstack->root_mount = m;
                }
        assert(has_root == !!mstack->root_mount);

        mstack->has_tmpfs_root = n_layers == 0 && !has_rw && !has_root_bind && !has_root;
        mstack->has_overlayfs = n_layers > 0 || has_rw;
        return 0;
}

static int mstack_load_now(MStack *mstack, const char *dir, int dir_fd, MStackFlags flags) {
        _cleanup_close_ int _dir_fd = -EBADF;
        int r;

        assert(mstack);

        r = free_and_strdup_warn(&mstack->path, dir);
        if (r < 0)
                return r;

        /* Expects dir_fd already opened. If not, then we'll open it based on 'dir' */
        if (dir_fd < 0) {
                _dir_fd = openat(AT_FDCWD, dir ?: ".", O_DIRECTORY|O_CLOEXEC);
                if (_dir_fd < 0)
                        return log_error_errno(errno, "Failed to to open '%s': %m", dir);

                dir_fd = _dir_fd;
        }

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dir_fd, RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                r = mstack_load_one(mstack, dir, dir_fd, (*i)->d_name);
                if (r < 0)
                        return r;
        }

        r = mstack_normalize(mstack);
        if (r < 0)
                return r;

        return 0;
}

static int mount_get_fd(MStackMount *m) {
        assert(m);

        if (m->dissected_image) {
                assert(m->dissected_image->partitions[PARTITION_ROOT].found);
                return ASSERT_FD(m->dissected_image->partitions[PARTITION_ROOT].fsmount_fd);
        }

        return m->what_fd;
}

int mstack_make_mounts(
                MStack *mstack,
                const ImagePolicy *image_policy,
                const ImageFilter *image_filter,
                MStackFlags flags) {
        int r;

        assert(mstack);

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                if (!IN_SET(m->image_type, IMAGE_RAW, IMAGE_BLOCK))
                        continue;

                DissectImageFlags dissect_image_flags =
                        (FLAGS_SET(flags, MSTACK_RDONLY) ? DISSECT_IMAGE_READ_ONLY : 0) |
                        DISSECT_IMAGE_DISCARD|
                        DISSECT_IMAGE_GENERIC_ROOT|
                        DISSECT_IMAGE_REQUIRE_ROOT|
                        DISSECT_IMAGE_MOUNT_ROOT_ONLY|
                        DISSECT_IMAGE_FSCK|
                        DISSECT_IMAGE_USR_NO_ROOT|
                        DISSECT_IMAGE_GROWFS|
                        DISSECT_IMAGE_ADD_PARTITION_DEVICES|
                        DISSECT_IMAGE_PIN_PARTITION_DEVICES|
                        DISSECT_IMAGE_ALLOW_USERSPACE_VERITY;

                _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
                r = loop_device_make(
                                m->what_fd,
                                FLAGS_SET(flags, MSTACK_RDONLY) ? O_RDONLY : O_RDWR,
                                /* offset= */ 0,
                                /* size= */ UINT64_MAX,
                                /* sector_size= */ UINT32_MAX,
                                LO_FLAGS_PARTSCAN,
                                LOCK_SH,
                                &loop_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate loopback device for '%s': %m", m->what);

                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
                _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
                r = dissect_loop_device_and_warn(
                                loop_device,
                                &verity,
                                /* mount_options= */ NULL,
                                image_policy,
                                image_filter,
                                dissect_image_flags,
                                &dissected_image);
                if (r < 0)
                        return r;

                if (!dissected_image->partitions[PARTITION_ROOT].found)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Currently images withot root partition are not supported: %m");

                r = dissected_image_load_verity_sig_partition(
                                dissected_image,
                                loop_device->fd,
                                &verity);
                if (r < 0)
                        return log_error_errno(r, "Failed to load Verity signature partition of '%s': %m", m->what);

                r = dissected_image_guess_verity_roothash(
                                dissected_image,
                                &verity);
                if (r < 0)
                        return log_error_errno(r, "Failed to guess Verity root hash of '%s': %m", m->what);

                r = dissected_image_decrypt(
                                dissected_image,
                                /* passphrase= */ NULL,
                                &verity,
                                image_policy,
                                dissect_image_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to decrypt image '%s': %m", m->what);

                r = dissected_image_mount(
                                dissected_image,
                                /* where= */ NULL,               /* allocate as mount fds, do not attach anywhere */
                                /* uid_shift= */ UID_INVALID,
                                /* uid_range= */ UID_INVALID,
                                /* userns_fd = */ -EBADF,
                                dissect_image_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount image '%s': %m", m->what);

                r = loop_device_flock(loop_device, LOCK_UN);
                if (r < 0)
                        return log_error_errno(r, "Failed to unlock loopback block device: %m");

                r = dissected_image_relinquish(dissected_image);
                if (r < 0)
                        return log_error_errno(r, "Failed to relinquish DM and loopback block devices: %m");

                m->dissected_image = TAKE_PTR(dissected_image);
        }

        _cleanup_close_ int overlayfs_mnt_fd = -EBADF;
        if (mstack->has_overlayfs) {
                _cleanup_free_ char *overlayfs_opts = NULL;
                bool writable = false;

                _cleanup_close_ int sb_fd = fsopen("overlay", FSOPEN_CLOEXEC);
                if (sb_fd < 0)
                        return log_error_errno(errno, "Failed to create overlayfs: %m");

                MStackMount *work = NULL;
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                        const char *f;
                        switch (m->mount_type) {
                        case MSTACK_RW:
                                if (!FLAGS_SET(flags, MSTACK_RDONLY)) {
                                        f = "upperdir";
                                        writable = true;
                                        break;
                                }

                                _fallthrough_;
                        case MSTACK_LAYER:
                                f = "lowerdir+";
                                break;
                        case MSTACK_WORK:
                                assert(!work);
                                work = m;
                                f = NULL;
                                break;
                        default:
                                f = NULL;
                        }

                        if (!f)
                                continue;

                        assert(mount_get_fd(m) >= 0);

                        if (fsconfig(sb_fd, FSCONFIG_SET_STRING, f, FORMAT_PROC_FD_PATH(mount_get_fd(m)), 0) < 0)
                                return log_error_errno(errno, "Failed to set mount layer %s=%s: %m", f, m->what);
                }

                assert(work || !writable);

                if (writable) {
                        if (fsconfig(sb_fd, FSCONFIG_SET_STRING, "workdir", FORMAT_PROC_FD_PATH(mount_get_fd(work)), 0) < 0)
                                return log_error_errno(errno, "Failed to set mount layer workdir=%s: %m", work->what);
                } else {
                        if (fsconfig(sb_fd, FSCONFIG_SET_FLAG, "ro", NULL, 0) < 0)
                                return log_error_errno(errno, "Failed to set read only mount flag: %m");
                }

                if (fsconfig(sb_fd, FSCONFIG_SET_STRING, "source", mstack->path, 0) < 0)
                        return log_error_errno(errno, "Failed to set mount source: %m");

                if (fsconfig(sb_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
                        return log_error_errno(errno, "Failed to realize overlayfs: %m");

                overlayfs_mnt_fd = fsmount(sb_fd, FSMOUNT_CLOEXEC, 0);
                if (overlayfs_mnt_fd < 0)
                        return log_error_errno(errno, "Failed to create mount fd: %m");

                if (mount_setattr(overlayfs_mnt_fd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = writable ? 0 : MOUNT_ATTR_RDONLY,
                                          .attr_clr = writable ? MOUNT_ATTR_RDONLY : 0,
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_error_errno(errno, "Failed to mark root bind mount read-only: %m");
        }

        assert(mstack->root_mount_fd < 0);
        if (mstack->root_mount) {
                assert(!mstack->has_tmpfs_root);

                mstack->root_mount_fd = open_tree(mount_get_fd(mstack->root_mount), /* filename= */ "", OPEN_TREE_CLONE|AT_EMPTY_PATH|OPEN_TREE_CLOEXEC);
                if (mstack->root_mount_fd < 0)
                        return log_error_errno(errno, "Failed to create root bind mount: %m");

                if (mount_setattr(mstack->root_mount_fd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = mstack->root_mount->mount_type == MSTACK_ROBIND || FLAGS_SET(flags, MSTACK_RDONLY) ? MOUNT_ATTR_RDONLY : 0,
                                          .attr_clr = mstack->root_mount->mount_type == MSTACK_ROBIND || FLAGS_SET(flags, MSTACK_RDONLY) ? 0 : MOUNT_ATTR_RDONLY,
                                          .propagation = MS_PRIVATE, /* disconnect us from bind mount source */
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_error_errno(errno, "Failed to mark root bind mount read-only: %m");

        } else if (mstack->has_tmpfs_root) {
                _cleanup_close_ int sb_fd = fsopen("tmpfs", FSOPEN_CLOEXEC);
                if (sb_fd < 0)
                        return log_error_errno(errno, "Failed to create tmpfs: %m");

                if (fsconfig(sb_fd, FSCONFIG_SET_STRING, "source", mstack->path, 0) < 0)
                        return log_error_errno(errno, "Failed to set mount source: %m");

                if (fsconfig(sb_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
                        return log_error_errno(errno, "Failed to realize tmpfs: %m");

                mstack->root_mount_fd = fsmount(sb_fd, FSMOUNT_CLOEXEC, 0);
                if (mstack->root_mount_fd < 0)
                        return log_error_errno(errno, "Failed to create mount fd: %m");
        }

        if (mstack->root_mount_fd >= 0 && overlayfs_mnt_fd >= 0) {
                /* If we have an overlayfs and a root fs, then the overlayfs should be placed on /usr/. */
                _cleanup_close_ int usr_fd = -EBADF;
                mstack->usr_mount_fd = open_tree(overlayfs_mnt_fd, "usr", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW);
                if (mstack->usr_mount_fd < 0)
                        return log_error_errno(errno, "Failed to create bind mount inode '/usr/': %m");

                if (mount_setattr(mstack->usr_mount_fd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = mstack->root_mount->mount_type == MSTACK_ROBIND || FLAGS_SET(flags, MSTACK_RDONLY) ? MOUNT_ATTR_RDONLY : 0,
                                          .attr_clr = mstack->root_mount->mount_type == MSTACK_ROBIND || FLAGS_SET(flags, MSTACK_RDONLY) ? 0 : MOUNT_ATTR_RDONLY,
                                          .propagation = MS_PRIVATE, /* disconnect us from bind mount source */
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_error_errno(errno, "Failed to mark usr bind mount read-only: %m");
        }

        /* If we acquired no other root fs, then the overlayfs is our root */
        if (mstack->root_mount_fd < 0)
                mstack->root_mount_fd = TAKE_FD(overlayfs_mnt_fd);

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {

                if (!IN_SET(m->mount_type, MSTACK_BIND, MSTACK_ROBIND) ||
                    m == mstack->root_mount)
                        continue;

                assert(m->mount_fd < 0);

                m->mount_fd = open_tree(mount_get_fd(m), /* filename= */ "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
                if (m->mount_fd < 0)
                        return log_error_errno(errno, "Failed to create bind mount inode '%s': %m", m->where);

                if (mount_setattr(m->mount_fd, "", AT_EMPTY_PATH|AT_RECURSIVE,
                                  &(struct mount_attr) {
                                          .attr_set = (m->mount_type == MSTACK_ROBIND || FLAGS_SET(flags, MSTACK_RDONLY)) ? MOUNT_ATTR_RDONLY : 0,
                                          .attr_clr = (m->mount_type == MSTACK_ROBIND || FLAGS_SET(flags, MSTACK_RDONLY)) ? 0 : MOUNT_ATTR_RDONLY,
                                          .propagation = MS_PRIVATE, /* disconnect us from bind mount source */
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_error_errno(errno, "Failed to mark bind mount read-only: %m");
        }

        return 0;
}

int mstack_bind_mounts(
                MStack *mstack,
                const char *where,
                int where_fd,
                MStackFlags flags,
                int *ret_root_fd) {

        int r;

        assert(mstack);

        _cleanup_close_ int _where_fd = -EBADF;
        if (where_fd == AT_FDCWD) {
                _where_fd = open(".", O_CLOEXEC|O_PATH|O_DIRECTORY);
                if (_where_fd < 0)
                        return log_error_errno(errno, "Failed to open current working directory: %m");
                where_fd = _where_fd;
        } else if (where_fd < 0) {
                r = chase(where,
                          /* root= */ NULL,
                          (FLAGS_SET(flags, MSTACK_MKDIR) ? CHASE_MKDIR_0755 : 0)|CHASE_MUST_BE_DIRECTORY,
                          /* ret_path= */ NULL,
                          &_where_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", where);

                where_fd = _where_fd;
        }

        assert(mstack->root_mount_fd >= 0);
        if (move_mount(mstack->root_mount_fd, "", where_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                return log_error_errno(errno, "Failed to attach mstack root mount to '%s': %m", where);

        _cleanup_close_ int root_fd = open(where, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0)
                return log_error_errno(errno, "Failed to mount root mount '%s': %m", where);

        if (mstack->usr_mount_fd >= 0) {
                _cleanup_close_ int subdir_fd = -EBADF;
                r = chaseat(root_fd, "usr", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &subdir_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open mount point inode '%s': %m", where);

                if (move_mount(mstack->usr_mount_fd, "", subdir_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                        return log_error_errno(errno, "Failed to attach bind mount to '/usr/' subdir: %m");
        }

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {

                if (!IN_SET(m->mount_type, MSTACK_BIND, MSTACK_ROBIND) ||
                    m == mstack->root_mount)
                        continue;

                assert(m->mount_fd >= 0);

                _cleanup_close_ int subdir_fd = -EBADF;
                r = chaseat(root_fd, m->where, CHASE_AT_RESOLVE_IN_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &subdir_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open mount point inode '%s': %m", m->where);

                if (move_mount(m->mount_fd, "", subdir_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                        return log_error_errno(errno, "Failed to attach bind mount to '%s' subdir: %m", m->where);
        }

        /* If we have a tmpfs root, the above might have created mount point inodes. Hence we left the tmpfs
         * writable for that. Let's fix that now. Also, let's enable propagation for the future */
        if (mount_setattr(root_fd, "", AT_EMPTY_PATH|AT_RECURSIVE,
                          &(struct mount_attr) {
                                  .attr_set = FLAGS_SET(flags, MSTACK_RDONLY) ? MOUNT_ATTR_RDONLY : 0,
                                  .attr_clr = FLAGS_SET(flags, MSTACK_RDONLY) ? 0 : MOUNT_ATTR_RDONLY,
                                  .propagation = MS_SHARED,
                          }, sizeof(struct mount_attr)) < 0)
                return log_error_errno(errno, "Failed to mark root bind mount read-only: %m");

        if (ret_root_fd)
                *ret_root_fd = TAKE_FD(root_fd);

        return 0;
}

int mstack_apply(
                const char *dir,
                int dir_fd,
                const char *where,
                const ImagePolicy *image_policy,
                const ImageFilter *image_filter,
                MStackFlags flags,
                int *ret_root_fd) {
        int r;

        assert(where);

        _cleanup_(mstack_done) MStack mstack = MSTACK_INIT;
        r = mstack_load_now(&mstack, dir, dir_fd, flags);
        if (r < 0)
                return r;

        r = mstack_make_mounts(&mstack, image_policy, image_filter, flags);
        if (r < 0)
                return r;

        return mstack_bind_mounts(&mstack, where, /* where_fd= */ -EBADF, flags, ret_root_fd);
}

int mstack_load(const char *dir,
                int dir_fd,
                MStack **ret) {

        int r;

        MStack *mstack = new(MStack, 1);
        if (!mstack)
                return -ENOMEM;

        *mstack = MSTACK_INIT;

        r = mstack_load_now(mstack, dir, dir_fd, /* flags= */ 0);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(mstack);

        return 0;
}

int mstack_is_read_only(MStack *mstack) {
        assert(mstack);

        if (mstack->has_tmpfs_root)
                return true;

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if (IN_SET(m->mount_type, MSTACK_ROOT, MSTACK_RW, MSTACK_BIND))
                        return false;

        return true;
}

static const char *const mstack_mount_type_table[] = {
        [MSTACK_ROOT]   = "root",
        [MSTACK_LAYER]  = "layer",
        [MSTACK_RW]     = "rw",
        [MSTACK_WORK]   = "work",
        [MSTACK_BIND]   = "bind",
        [MSTACK_ROBIND] = "robind",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(mstack_mount_type, MStackMountType);
