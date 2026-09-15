/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "chase.h"
#include "dissect-image.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "loop-util.h"
#include "macro.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "unit-name.h"
#include "user-util.h"
#include "volatile-util.h"
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
        mstack->tmpfs_selinux_context = mfree(mstack->tmpfs_selinux_context);
        safe_close(mstack->root_mount_fd);
        safe_close(mstack->usr_extract_fd);
}

MStack* mstack_free(MStack *mstack) {
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
        if (isempty(a)) {
                if (ret_parameter)
                        *ret_parameter = NULL;

                return false;
        }

        p = strdup(a);
        if (!p)
                return -ENOMEM;

        if (ret_parameter)
                *ret_parameter = TAKE_PTR(p);

        return true;
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
                return log_debug_errno(errno, "Failed to open %s/%s: %m", dir, fname);

        struct stat st;
        if (fstat(what_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat %s/%s: %m", dir, fname);

        ImageType image_type = _IMAGE_TYPE_INVALID;
        _cleanup_free_ char *what = NULL, *unsuffixed = NULL;
        if (S_ISDIR(st.st_mode)) {

                const char *dotv = endswith(fname, ".v");
                if (dotv) {
                        const char *dotrawv = endswith(fname, ".raw.v");

                        PickFilter filter = {
                                .type_mask = dotrawv ? (1U << DT_REG) : ((1U << DT_DIR) | (1U << DT_BLK)),
                                .suffix = dotrawv ? ".raw" : NULL,
                                .architecture = _ARCHITECTURE_INVALID,
                        };

                        _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                        r = path_pick(dir, dir_fd, dir_fd, fname, &filter, /* n_filters= */ 1, PICK_ARCHITECTURE, &result);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to resolve '%s' directory: %m", fname);
                        if (r == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT), "Found no suitable entry in '%s': %m", fname);

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
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected suffix of '%s/%s', refusing.", dir, fname);

                unsuffixed = strndup(fname, e - fname);
                if (!unsuffixed)
                        return -ENOMEM;

                image_type = IMAGE_RAW;

        } else if (S_ISBLK(st.st_mode))
                image_type = IMAGE_BLOCK;
        else
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected inode type of '%s/%s', refusing.", dir, fname);

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
                return log_debug_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
        if (r > 0) {
                /* Paranoia: let's refuse two layers that have the same sort key. Howe can that happen?
                 * People might have a .raw layer and one dir layer with the same name. Or one with .v and
                 * one without. */
                if (mstack_find(mstack, MSTACK_LAYER, parameter, /* where= */ NULL))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Duplicate layer '%s', refusing.", parameter);

                *m = (MStackMount) {
                        .mount_type = MSTACK_LAYER,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .sort_key = TAKE_PTR(parameter),
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                log_debug("Found mstack layer '%s' ('%s', owned by UID " UID_FMT ")", m->sort_key, m->what, st.st_uid);
                return 0;
        }

        if (streq(unsuffixed, "rw")) {
                if (mstack_find(mstack, MSTACK_RW, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Duplicate rw entry, refusing.");

                *m = (MStackMount) {
                        .mount_type = MSTACK_RW,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                log_debug("Found mstack rw layer ('%s')", m->what);
                return 0;
        }

        MStackMountType bind_type = _MSTACK_MOUNT_TYPE_INVALID;
        r = validate_prefix_name(unsuffixed, "bind@", &parameter);
        if (r < 0)
                return log_debug_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
        if (r > 0)
                bind_type = MSTACK_BIND;
        else {
                r = validate_prefix_name(unsuffixed, "robind@", &parameter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
                if (r > 0)
                        bind_type = MSTACK_ROBIND;
        }
        if (bind_type >= 0) {
                _cleanup_free_ char *where = NULL;
                r = unit_name_path_unescape(parameter, &where);
                if (r < 0)
                        return log_debug_errno(r, "Cannot unescape path '%s' of '%s/%s'", parameter, dir, fname);

                if (mstack_find(mstack, MSTACK_BIND, /* sort_key= */ NULL, /* where= */ where) ||
                    mstack_find(mstack, MSTACK_ROBIND, /* sort_key= */ NULL, /* where= */ where))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Duplicate bind entry, refusing");

                *m = (MStackMount) {
                        .mount_type = bind_type,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .where = TAKE_PTR(where),
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                log_debug("Found mstack bind layer '%s' ('%s')", empty_to_root(m->where), m->what);
                return 0;
        }

        r = validate_prefix_name(unsuffixed, "tmpfs@", &parameter);
        if (r < 0)
                return log_debug_errno(r, "Failed to check prefix of %s/%s: %m", dir, fname);
        if (r > 0) {
                _cleanup_free_ char *where = NULL;
                r = unit_name_path_unescape(parameter, &where);
                if (r < 0)
                        return log_debug_errno(r, "Cannot unescape path '%s' of '%s/%s'", parameter, dir, fname);

                if (mstack_find(mstack, MSTACK_TMPFS, /* sort_key= */ NULL, /* where= */ where))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Duplicate tmpfs entry, refusing");

                *m = (MStackMount) {
                        .mount_type = MSTACK_TMPFS,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .where = TAKE_PTR(where),
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                log_debug("Found mstack tmpfs layer '%s' ('%s')", empty_to_root(m->where), m->what);
                return 0;
        }

        if (streq(unsuffixed, "root")) {
                if (mstack_find(mstack, MSTACK_ROOT, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Duplicate root entry, refusing");

                *m = (MStackMount) {
                        .mount_type = MSTACK_ROOT,
                        .what = TAKE_PTR(what),
                        .what_fd = TAKE_FD(what_fd),
                        .mount_fd = -EBADF,
                        .image_type = image_type,
                };

                mstack->n_mounts++;
                log_debug("Found mstack root layer ('%s')", m->what);
                return 0;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unrecognized entry '%s/%s', refusing", dir, fname);
}

static int mount_compare_func(const MStackMount *a, const MStackMount *b) {
        int r;

        assert(a);
        assert(b);

        /* If we apply this mstack in read-only mode then we'll convert the 'rw' layer which normally is an
         * upperdir into the topmost lowerdir. When sorting the mstack it is hence essential, that the "rw"
         * layer ends up *after* the regular layers. Enforce this here via a compile-time check. */
        assert_cc(MSTACK_RW > MSTACK_LAYER);

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
        bool has_rw = false, has_synthetic_rw = false, has_root_bind = false, has_usr_bind = false, has_root = false;
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                switch (m->mount_type) {
                case MSTACK_LAYER:
                        n_layers++;
                        break;

                case MSTACK_RW:
                        assert(!has_rw);
                        has_rw = true;
                        /* A synthetic rw layer (e.g. from --volatile=overlay) has no backing yet - it is
                         * only realized into a throwaway tmpfs later, in mstack_make_mounts(). Track it
                         * separately: it can't be collapsed into a MSTACK_BIND below like a real rw/
                         * entry could, since there's nothing to bind-mount yet. */
                        has_synthetic_rw = m->synthetic;
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

                case MSTACK_TMPFS:
                        /* A fresh tmpfs submount on top; doesn't participate in the overlayfs stack. */
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

        /* A lone synthetic rw layer (e.g. a bare --volatile=overlay with nothing else in the .mstack/) has
         * no backing fd to turn into a bind mount below - there's nothing to bind-mount yet, it's only
         * realized into a throwaway tmpfs later, in mstack_make_mounts(). Drop it instead: with nothing
         * else left, has_tmpfs_root below naturally becomes true, and mstack_make_mounts() already
         * creates a fresh writable tmpfs root unconditionally in that case - the exact same end result a
         * bind mount would have produced, once realized. */
        if (!has_root && n_layers == 0 && has_rw && has_synthetic_rw) {
                mstack_remove(mstack, MSTACK_RW);
                has_rw = false;
        }

        /* Only a single read-only or read-write layer, and no root/ to combine it with? Turn into bind
         * mount! (If root/ is present, always build a real overlay below instead, with root/ folded in
         * as the base layer, so root/ and the layer/rw content merge across the whole tree rather than
         * just /usr/.) */
        if (!has_root && n_layers + has_rw == 1) {
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                        if (m->mount_type == MSTACK_LAYER)
                                m->mount_type = MSTACK_ROBIND;
                        else if (m->mount_type == MSTACK_RW)
                                m->mount_type = MSTACK_BIND;
                        else
                                continue;

                        r = free_and_strdup_warn(&m->where, "/");
                        if (r < 0)
                                return r;

                        has_root_bind = true;
                }

                n_layers = 0;
                has_rw = false;
        }

        /* If the root dir is overmounted, we can drop the original root */
        if (has_root_bind) {
                mstack_remove(mstack, MSTACK_ROOT);
                has_root = false;
        }

        /* After converting, let's sort things again */
        typesafe_qsort(mstack->mounts, mstack->n_mounts, mount_compare_func);

        /* Find root mount (unless it's the overlayfs stack). Reset first: mstack_normalize() can run
         * more than once on the same MStack (e.g. mstack_merge_volatile() re-normalizes after mutating
         * topology), and a stale pointer from an earlier call must not survive if the root candidate's
         * identity changed (or disappeared) since then. */
        mstack->root_mount = NULL;
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if ((m->mount_type == MSTACK_ROOT) ||
                    (IN_SET(m->mount_type, MSTACK_BIND, MSTACK_ROBIND) && empty_or_root(m->where))) {
                        assert(!mstack->root_mount);
                        mstack->root_mount = m;
                }
        assert((has_root || has_root_bind) == !!mstack->root_mount);

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
                _dir_fd = openat(AT_FDCWD, isempty(dir) ? "." : dir, O_DIRECTORY|O_CLOEXEC);
                if (_dir_fd < 0)
                        return log_debug_errno(errno, "Failed to open '%s': %m", dir);

                dir_fd = _dir_fd;
        } else {
                /* Possibly convert an O_PATH fd to a real one */
                dir_fd = fd_reopen_condition(dir_fd, O_DIRECTORY|O_CLOEXEC, O_PATH|O_DIRECTORY, &_dir_fd);
                if (dir_fd < 0)
                        return log_debug_errno(dir_fd, "Failed to reopen '%s': %m", dir);
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

        return mstack_normalize(mstack);
}

static int mount_get_fd(MStackMount *m) {
        assert(m);

        if (m->dissected_image) {
                assert(m->dissected_image->partitions[PARTITION_ROOT].found);
                return ASSERT_FD(m->dissected_image->partitions[PARTITION_ROOT].fsmount_fd);
        }

        if (m->mount_fd >= 0)
                return m->mount_fd;

        /* Falling through to what_fd here would hand out the source inode rather than the mount, which is
         * silently the wrong object for anything mount-related. Once the fd has been consumed by an attach
         * there is no mount handle left to give, so say so instead. */
        if (m->fd_consumed)
                return -EBADF;

        return m->what_fd;
}

int mstack_new_from_root_fd(int root_fd, MStack **ret) {
        _cleanup_close_ int root_fd_close = root_fd;
        int r;

        assert(root_fd >= 0);
        assert(ret);

        _cleanup_(mstack_freep) MStack *mstack = new(MStack, 1);
        if (!mstack)
                return -ENOMEM;

        *mstack = MSTACK_INIT;

        if (!GREEDY_REALLOC(mstack->mounts, 1))
                return -ENOMEM;

        /* Wrap the already-mounted root as a single MSTACK_ROOT entry. We take ownership of root_fd. */
        mstack->mounts[0] = (MStackMount) {
                .mount_type = MSTACK_ROOT,
                .what_fd = -EBADF,
                .mount_fd = TAKE_FD(root_fd_close),
                .image_type = IMAGE_DIRECTORY,
        };
        mstack->n_mounts = 1;

        r = mstack_normalize(mstack);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(mstack);
        return 0;
}

int mstack_merge_volatile(
                MStack *mstack,
                VolatileMode mode,
                uid_t tmpfs_uid_shift,
                const char *tmpfs_selinux_context) {

        int r;

        assert(mstack);

        /* Remember the tmpfs parity settings, before the VOLATILE_NO exit rather than after it: a stack
         * can carry tmpfs@ entries of its own with no --volatile= in sight, and those need the same
         * uid=/gid= and SELinux context. Storing them here keeps this the field's only writer. */
        mstack->tmpfs_uid_shift = tmpfs_uid_shift;
        r = free_and_strdup_warn(&mstack->tmpfs_selinux_context, tmpfs_selinux_context);
        if (r < 0)
                return r;

        if (mode == VOLATILE_NO)
                return 0;

        switch (mode) {

        case VOLATILE_OVERLAY:
                /* Demote any plain root into a read-only lower layer so the overlay covers the whole tree
                 * (not just /usr/), then add a synthetic writable upper layer on a throwaway tmpfs. */
                FOREACH_MSTACK_MOUNT_TYPE(m, mstack, MSTACK_ROOT)
                        m->mount_type = MSTACK_LAYER;

                if (mstack_find(mstack, MSTACK_RW, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Cannot add volatile overlay: mount stack already has a writable layer.");

                if (!GREEDY_REALLOC(mstack->mounts, mstack->n_mounts + 1))
                        return -ENOMEM;

                mstack->mounts[mstack->n_mounts++] = (MStackMount) {
                        .mount_type = MSTACK_RW,
                        .what_fd = -EBADF,
                        .mount_fd = -EBADF,
                        .synthetic = true, /* backing is realized in mstack_make_mounts() */
                        .image_type = _IMAGE_TYPE_INVALID,
                };
                break;

        case VOLATILE_STATE: {
                /* Keep the existing root read-only, and mount a fresh tmpfs on /var/ on top. */
                if (mstack_find(mstack, MSTACK_TMPFS, /* sort_key= */ NULL, "/var"))
                        break;

                _cleanup_free_ char *where = strdup("/var");
                if (!where)
                        return -ENOMEM;

                if (!GREEDY_REALLOC(mstack->mounts, mstack->n_mounts + 1))
                        return -ENOMEM;

                mstack->mounts[mstack->n_mounts++] = (MStackMount) {
                        .mount_type = MSTACK_TMPFS,
                        .what_fd = -EBADF,
                        .mount_fd = -EBADF,
                        .where = TAKE_PTR(where),
                        .image_type = _IMAGE_TYPE_INVALID,
                        .from_volatile = true,
                };
                break;
        }

        case VOLATILE_YES:
                /* Replace the root with a throwaway tmpfs, keeping only /usr/ from the prepared tree,
                 * read-only. Since root/ (if any) is now folded directly into the same overlay as
                 * layer@/rw (see mstack_merge_volatile()'s VOLATILE_OVERLAY case and
                 * mstack_make_overlayfs()), there's no longer a way to cleanly pull /usr/ out of an
                 * individual entry before assembly - root/ and layer@/rw may need to merge across the
                 * whole tree first. So this is deferred: just validate here that there is SOMETHING to
                 * extract /usr/ from, and let mstack_make_mounts() do the actual extraction once it has
                 * a fully assembled tree to clone /usr/ out of (see extract_usr_only there). */
                if (!mstack->root_mount && !mstack->has_overlayfs)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "--volatile=yes requires a root directory or layer@ content to extract /usr/ from.");

                mstack->extract_usr_only = true;
                return 0;

        default:
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unsupported volatile mode for mstack merge.");
        }

        return mstack_normalize(mstack);
}

static bool mount_is_ro(MStack *mstack, MStackMount *m, MStackFlags flags) {
        assert(mstack);
        assert(m);

        /* root/ is always folded into the overlay as its base layer when one exists (see
         * mstack_make_overlayfs()), so from that point on it must be treated exactly like any other
         * read-only layer: nothing should ever write into it directly again, only into rw/'s upperdir. */
        return FLAGS_SET(flags, MSTACK_RDONLY) ||
                IN_SET(m->mount_type, MSTACK_LAYER, MSTACK_ROBIND) ||
                (m->mount_type == MSTACK_ROOT && mstack->has_overlayfs);
}

static const char* mount_name(MStackMount *m) {
        assert(m);

        /* Returns some vaguely useful identifier for this layer, for showing in debug output */

        if (m->sort_key)
                return m->sort_key;

        if (m->where)
                return m->where;

        return mstack_mount_type_to_string(m->mount_type);
}

int mstack_open_images(
                MStack *mstack,
                sd_varlink *mountfsd_link,
                int userns_fd,
                const ImagePolicy *image_policy,
                const ImageFilter *image_filter,
                MStackFlags flags) {

        int r;

        assert(mstack);

        _cleanup_(sd_varlink_unrefp) sd_varlink *_vl = NULL;
        if (userns_fd >= 0 && !mountfsd_link) {
                /* User a single connection for all mounts */
                r = mountfsd_connect(&_vl);
                if (r < 0)
                        return r;

                mountfsd_link = _vl;
        }

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {

                /* A tmpfs submount is created fresh at attach time; there's no backing image to open. */
                if (m->mount_type == MSTACK_TMPFS)
                        continue;

                /* Synthetic entries (e.g. a --volatile= root/rw layer) already carry a ready-made mount
                 * fd (or get one later); there's nothing on disk to open here. */
                if (m->what_fd < 0)
                        continue;

                DissectImageFlags dissect_image_flags =
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

                SET_FLAG(dissect_image_flags, DISSECT_IMAGE_READ_ONLY, mount_is_ro(mstack, m, flags));
                SET_FLAG(dissect_image_flags, DISSECT_IMAGE_FOREIGN_UID, userns_fd >= 0);

                switch (m->image_type) {

                case IMAGE_RAW:
                case IMAGE_BLOCK:
                        assert(!m->dissected_image);

                        if (userns_fd >= 0) {
                                r = mountfsd_mount_image_fd(
                                                mountfsd_link,
                                                m->what_fd,
                                                userns_fd,
                                                /* options= */ NULL,
                                                image_policy,
                                                /* verity= */ NULL,
                                                dissect_image_flags,
                                                &m->dissected_image);
                                if (r < 0)
                                        return r;
                        } else {
                                _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
                                _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;

                                r = loop_device_make_by_path_at(
                                                m->what_fd,
                                                /* path= */ NULL,
                                                FLAGS_SET(flags, MSTACK_RDONLY) ? O_RDONLY : -1,
                                                /* sector_size= */ UINT32_MAX,
                                                LO_FLAGS_PARTSCAN,
                                                LOCK_SH,
                                                &loop_device);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to allocate loopback device for '%s': %m", m->what);

                                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
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
                                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Currently images without root partition are not supported: %m");

                                r = dissected_image_load_verity_sig_partition(
                                                dissected_image,
                                                loop_device->fd,
                                                &verity);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to load Verity signature partition of '%s': %m", m->what);

                                r = dissected_image_guess_verity_roothash(
                                                dissected_image,
                                                &verity);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to guess Verity root hash of '%s': %m", m->what);

                                r = dissected_image_decrypt(
                                                dissected_image,
                                                /* root= */ NULL,
                                                /* passphrase= */ NULL,
                                                &verity,
                                                image_policy,
                                                dissect_image_flags);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to decrypt image '%s': %m", m->what);

                                r = dissected_image_mount(
                                                dissected_image,
                                                /* where= */ NULL,               /* allocate as mount fds, do not attach anywhere */
                                                /* uid_shift= */ UID_INVALID,
                                                /* uid_range= */ UID_INVALID,
                                                /* userns_fd = */ -EBADF,
                                                dissect_image_flags);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to mount image '%s': %m", m->what);

                                r = loop_device_flock(loop_device, LOCK_UN);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to unlock loopback block device: %m");

                                r = dissected_image_relinquish(dissected_image);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to relinquish DM and loopback block devices: %m");

                                m->dissected_image = TAKE_PTR(dissected_image);
                        }

                        log_debug("Acquired mstack DDI layer '%s'", mount_name(m));
                        break;

                case IMAGE_DIRECTORY:
                case IMAGE_SUBVOLUME:
                        assert(m->mount_fd < 0);

                        if (userns_fd >= 0) {
                                r = mountfsd_mount_directory_fd(
                                                mountfsd_link,
                                                m->what_fd,
                                                userns_fd,
                                                dissect_image_flags,
                                                &m->mount_fd);
                                if (r < 0)
                                        return r;
                        } else {
                                m->mount_fd = open_tree_attr_with_fallback(
                                                mount_get_fd(m),
                                                /* path= */ "",
                                                OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH,
                                                &(struct mount_attr) {
                                                        .attr_set = mount_is_ro(mstack, m, flags) ? MOUNT_ATTR_RDONLY : 0,
                                                        .attr_clr = mount_is_ro(mstack, m, flags) ? 0 : MOUNT_ATTR_RDONLY,
                                                        .propagation = MS_PRIVATE, /* disconnect us from bind mount source */
                                                });
                                if (m->mount_fd < 0)
                                        return log_debug_errno(m->mount_fd, "Failed to create bind mount inode '%s': %m", m->where);
                        }

                        log_debug("Acquired bind mount for layer '%s'.", mount_name(m));
                        break;

                default:
                        assert_not_reached();
                }
        }

        return 0;
}

bool mstack_has_writable_layers(MStack *mstack, MStackFlags flags) {
        assert(mstack);

        if (FLAGS_SET(flags, MSTACK_RDONLY))
                return false;

        return mstack_find(mstack, MSTACK_RW, /* sort_key= */ NULL, /* where= */ NULL);
}

/* One thing about the kernel underneath us that this code has to know and cannot derive from a version
 * number: whether overlayfs will take a layer as an fd. Distributions back-port partially, so a kernel
 * can report a version that has the feature while the feature does not work - a uname() check would be
 * wrong on exactly the kernels that need the fallback. Ask the kernel instead, once per process.
 *
 * The subsystem's other compatibility question - whether an incrementally built "lowerdir+" stack will
 * realize - is deliberately NOT cached here; see mstack_probe_layer_fd() for why it is answered
 * reactively instead.
 *
 * Every probe fails safe. On any error at all - no overlayfs module, a sandbox that forbids the mount, an
 * unprivileged caller with no mountfsd - the answer is "no", which selects the conservative path this
 * code took unconditionally before the probes existed. That means a probe failing for the wrong reason
 * costs performance and never correctness, but it also means it is silent, hence the debug logging. */
typedef struct MStackCaps {
        bool layer_fd;              /* overlayfs accepts FSCONFIG_SET_FD for layer parameters (6.13) */
} MStackCaps;

static int mstack_probe_scratch_tmpfs(void) {
        return make_fsmount(LOG_DEBUG, "mstack-probe", "tmpfs", /* flags= */ 0, "mode=0755",
                            /* userns_fd= */ -EBADF);
}

/* Asks whether overlayfs will take a layer as an fd rather than as a path.
 *
 * Deliberately does not try to answer whether an incrementally built "lowerdir+" stack will realize: on
 * the kernels where it does not, every fsconfig() succeeds and only FSCONFIG_CMD_CREATE fails, and a
 * probe built out of scratch tmpfs mounts reports success where the real layers still fail. So that one
 * is answered reactively instead, by the joined-"lowerdir=" fallback in mstack_overlay_assemble(). */
static void mstack_probe_layer_fd(MStackCaps *c) {
        assert(c);

        _cleanup_close_ int lower_fd = mstack_probe_scratch_tmpfs();
        if (lower_fd < 0)
                return (void) log_debug_errno(lower_fd, "mstack probe: no scratch tmpfs, assuming layers cannot be passed as fds: %m");

        _cleanup_close_ int sb_fd = fsopen("overlay", FSOPEN_CLOEXEC);
        if (sb_fd < 0)
                return (void) log_debug_errno(errno, "mstack probe: cannot open an overlayfs superblock: %m");

        if (fsconfig(sb_fd, FSCONFIG_SET_FD, "lowerdir+", /* value= */ NULL, lower_fd) < 0)
                return (void) log_debug_errno(errno, "mstack probe: 'lowerdir+' does not take an fd: %m");

        c->layer_fd = true;
}

static const MStackCaps* mstack_caps(void) {
        static MStackCaps cache = {};
        static bool cached = false;

        if (cached)
                return &cache;

        /* On a kernel that has all of this the fallback paths are unreachable, and an unreachable
         * fallback is an untested one. This lets the test suite take them. */
        if (secure_getenv_bool("SYSTEMD_MSTACK_ASSUME_NO_CAPS") > 0)
                log_debug("mstack probe: SYSTEMD_MSTACK_ASSUME_NO_CAPS is set, assuming the kernel supports none of it.");
        else if (mount_new_api_supported())
                mstack_probe_layer_fd(&cache);
        else
                log_debug("mstack probe: no new mount API, assuming nothing.");

        log_debug("mstack capabilities: layer_fd=%s", yes_no(cache.layer_fd));

        cached = true;
        return &cache;
}

static int fsconfig_add_layer(int sb_fd, const char *key, int layer_fd) {
        int r;

        assert(sb_fd >= 0);
        assert(key);
        assert(layer_fd >= 0);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *pretty = NULL;
                (void) fd_get_path(layer_fd, &pretty);
                log_debug("Adding '%s' as layer '%s' to overlayfs.", key, pretty);
        }

        /* overlayfs learnt support for FSCONFIG_SET_FD only with linux 6.13. On kernels 6.5-6.12, the
         * overlayfs parameter parser recognises the key but rejects the fd type with EINVAL. We used to
         * discover that here, per layer, on every layer of every stack; mstack_caps() has asked once. */

        // FIXME: This compatibility code path shall be removed once kernel 6.13
        //        becomes the new minimal baseline

        if (!mstack_caps()->layer_fd)
                return RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_STRING, key, FORMAT_PROC_FD_PATH(layer_fd), /* aux= */ 0));

        r = RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_FD, key, /* value= */ NULL, layer_fd));
        if (r != -EBADF && r != -EINVAL && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return r;

        /* The probe said fds are accepted and this one was not. Not something we expect, so say so, but
         * the string form still works and there is no reason to fail the mount over it. */
        const char *layer_path = FORMAT_PROC_FD_PATH(layer_fd);
        log_debug_errno(r, "FSCONFIG_SET_FD for layer '%s' failed despite being supported, falling back to '%s': %m",
                        key, layer_path);
        return RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_STRING, key, layer_path, /* aux= */ 0));
}

static int mstack_make_userns(MStack *mstack, uid_t uid_shift) {
        assert(mstack);

        /* All idmaps applied while assembling a stack share the caller's mapping/range, so that a caller
         * which lets us idmap the assembled root (instead of remounting it idmapped itself afterwards)
         * gets exactly the mapping it asked for. */
        assert(mstack->uid_range > 0); /* MSTACK_INIT establishes the default; nothing may clear it. */

        return make_userns(uid_shift,
                           mstack->uid_range,
                           /* source_owner= */ UID_INVALID,
                           /* dest_owner= */ UID_INVALID,
                           mstack->idmapping);
}

static int mstack_attach_temporarily(int mount_fd, const char *where) {
        assert(mount_fd >= 0);
        assert(where);

        /* A detached mount - one from fsmount(), or from an earlier open_tree(OPEN_TREE_CLONE) - is not
         * a valid starting point for everything the kernel lets you do with an attached one, and we hit
         * that restriction from two directions:
         *
         *   - overlayfs (detached-mount support arrived in 6.14) insists that upperdir be the root inode
         *     of its mount, which collides with the separate requirement that upperdir and workdir be
         *     siblings on the same mount;
         *   - open_tree(OPEN_TREE_CLONE) on a *subdirectory* of a detached mount is refused outright on
         *     some kernels.
         *
         * Attaching the mount somewhere, even momentarily, relaxes both. Callers running in a throwaway
         * mount namespace can simply leave it attached and let the namespace clean up; callers in the
         * caller's own namespace must umount2(where, MNT_DETACH) once they are done, on every path. */
        if (move_mount(mount_fd, "", -EBADF, where, MOVE_MOUNT_F_EMPTY_PATH) < 0)
                return log_debug_errno(errno, "Failed to temporarily attach mount to '%s': %m", where);

        return 0;
}

static int mstack_make_tmpfs(MStack *mstack, const char *limits, int *ret_mnt_fd) {
        _cleanup_free_ char *options = NULL;
        int r;

        assert(mstack);
        assert(ret_mnt_fd);

        /* Creates a fresh tmpfs mount fd. On top of the base 'mode=0755' and the passed size/inode limits
         * we also apply uid=/gid= and the SELinux 'context=' (when plumbed in), for parity with nspawn's
         * volatile tmpfs handling.
         *
         * The context deliberately does NOT go into the comma-separated option string. tmpfs_patch_options()
         * wraps it in quotes (context="...") for the legacy mount(2) parser its other callers still use, and
         * make_fsmount() would hand those quotes straight to fsconfig(), which the SELinux fs_context parser
         * does not strip. Dropping the quotes is not enough either: make_fsmount() splits its option string
         * on commas, and an MCS/sVirt context carries commas between its categories
         * (...:s0:c123,c456), so it would arrive truncated with the trailing categories offered as bogus
         * standalone flags. Pass it as a discrete key/value pair instead, which reaches fsconfig() whole. */
        const char *base = strjoina("mode=0755", strempty(limits));
        r = tmpfs_patch_options(base, mstack->tmpfs_uid_shift, /* selinux_apifs_context= */ NULL, &options);
        if (r < 0)
                return log_oom_debug();

        _cleanup_strv_free_ char **discrete_options = NULL;
#if HAVE_SELINUX
        /* Guarded like tmpfs_patch_options()' own 'context=' handling: the context is settable (nspawn
         * -L) regardless of how we were built, but make_fsmount_full() treats a rejected discrete option
         * as a hard error - so on a build without SELinux support offering it would turn a quietly
         * dropped option into a container that will not start. */
        if (mstack->tmpfs_selinux_context &&
            strv_extendf(&discrete_options, "context=%s", mstack->tmpfs_selinux_context) < 0)
                return log_oom_debug();
#endif

        int mnt_fd = make_fsmount_full(
                        LOG_DEBUG,
                        empty_to_root(mstack->path),
                        "tmpfs",
                        MS_STRICTATIME,
                        options,
                        discrete_options,
                        /* userns_fd= */ -EBADF);
        if (mnt_fd < 0)
                return mnt_fd;

        *ret_mnt_fd = mnt_fd;
        return 0;
}

/* Sets the remaining overlayfs mount options and materializes the superblock. Split out of
 * mstack_make_overlayfs() below so it can be called a second time, on a second superblock, as part of
 * the "lowerdir+" EINVAL fallback described there. */
static int mstack_overlayfs_create(int sb_fd, bool writable, const char *source) {
        assert(sb_fd >= 0);
        assert(source);

        if (!writable && fsconfig(sb_fd, FSCONFIG_SET_FLAG, "ro", /* value= */ NULL, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to set read-only mount flag: %m");

        if (fsconfig(sb_fd, FSCONFIG_SET_FLAG, "userxattr", /* value= */ NULL, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to set userxattr mount flag: %m");

        if (fsconfig(sb_fd, FSCONFIG_SET_STRING, "source", source, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to set mount source: %m");

        /* This is where the superblock is materialized. It must be called from the child's namespace,
         * where the mounts are attached as described above, otherwise overlayfs is unhappy and will
         * refuse the superblock to be created.
         *
         * Logged rather than returned bare: this runs inside the forked child, whose only channel back to
         * the parent is an errno, so an unlogged failure here is indistinguishable from every other
         * failure in that child.
         *
         * EBUSY is reported at error level, the same exception the other two error-level messages in this
         * file are made for: it is actionable guidance the caller cannot reconstruct. All it receives is
         * EBUSY, which it renders as "Device or resource busy" - true and useless. overlayfs refuses an
         * upperdir or workdir that another overlay still holds, so what it actually means is that a
         * previous mount over the same rw/ layer has not finished going away, and a caller looping
         * unmount/mount over one stack is racing its own teardown. Saying so here is what makes that
         * legible without the operator having to raise the log level on a running system first. */
        if (fsconfig(sb_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0) < 0) {
                if (errno == EBUSY)
                        return log_error_errno(errno,
                                               "Failed to realize overlayfs superblock for '%s': its upperdir or workdir is "
                                               "still held by another overlay mount - a previous mount over the same rw/ "
                                               "layer has not finished being torn down: %m", source);

                return log_debug_errno(errno, "Failed to realize overlayfs superblock for '%s': %m", source);
        }

        return 0;
}

/* The per-layer half of mstack_make_overlayfs(), which otherwise runs to a couple of hundred lines at nine
 * levels of indentation inside a forked child. Everything the step needs, and the fds it hands back, travel
 * in here rather than as a dozen parameters. */
typedef struct MStackOverlayBuilder {
        /* Inputs */
        int sb_fd;                  /* the superblock being configured */
        const char *temp_mount_dir; /* where each layer is attached for as long as it takes to open it */
        int uidmap_userns_fd;       /* idmap for the read-only layers, or -EBADF for none */
        const MStackPlan *plan;     /* every decision, made before any of this was mounted */

        /* Outputs. These fds stay open past their loop iteration on purpose: if the incremental
         * "lowerdir+" attempt fails with EINVAL we have to name them again, via FORMAT_PROC_FD_PATH(),
         * to build the joined "lowerdir=" fallback. */
        int *lower_fds;
        size_t n_lower_fds;
        int upperdir_fd;
        int workdir_fd;
} MStackOverlayBuilder;

static void mstack_overlay_builder_done(MStackOverlayBuilder *b) {
        assert(b);

        /* Only the array itself - the fds in it are owned by a child that is about to _exit(). */
        b->lower_fds = mfree(b->lower_fds);
}

/* The single place that decides how a layer's ownership is made to line up with the container's. Both
 * answers used to be inlined at the point they were applied, several hundred lines apart, with the rule
 * relating them written down nowhere - which is how they came to disagree.
 *
 * Read-only layers are idmapped. That is what lets an unshifted base image be read by a shifted container,
 * and it is the only reason idmapping was ever wanted here.
 *
 * The writable layer must NOT be idmapped, however tempting the symmetry. overlayfs creates a private
 * 'work/work' bookkeeping directory inside the workdir while materializing the superblock, and every later
 * write into the upperdir - including everything nspawn still creates in the fresh root before the payload
 * runs: base_filesystem_create(), custom --bind= mountpoints, /var/log/journal - goes through the same fd
 * as the real, unmapped caller. An idmapped mount refuses inode creation from outside its range with
 * EOVERFLOW, and for the work/work case the kernel does not fail the mount: it silently falls back to
 * mounting read-only. Nothing notices, and the root stays unusable for the container's whole lifetime.
 *
 * So the writable layer is chowned instead - but only when the payload will actually run shifted, which is
 * what tmpfs_uid_shift means and what uid_shift does not. uid_shift says merely that the layers are being
 * idmapped; a caller can ask for that while its payload still runs as real root (nspawn's --mstack= path),
 * and there root writes through the layer regardless, so chowning would rewrite ownership inside the
 * caller's persistent rw/ directory to no purpose. */
static MStackLayerIdentity mstack_layer_identity(
                const MStack *mstack,
                bool idmap_requested,
                bool writable_layer,
                uid_t *ret_uid) {

        assert(mstack);
        assert(ret_uid);

        if (writable_layer) {
                if (!uid_is_valid(mstack->tmpfs_uid_shift))
                        return MSTACK_LAYER_IDENTITY_NONE;

                *ret_uid = mstack->tmpfs_uid_shift;
                return MSTACK_LAYER_IDENTITY_CHOWN;
        }

        if (!idmap_requested)
                return MSTACK_LAYER_IDENTITY_NONE;

        *ret_uid = UID_INVALID; /* carried by the userns fd, not as a number */
        return MSTACK_LAYER_IDENTITY_IDMAP;
}

MStackPlan* mstack_plan_free(MStackPlan *plan) {
        if (!plan)
                return NULL;

        free(plan->layers);
        return mfree(plan);
}

static const MStackLayerPlan* mstack_plan_find(const MStackPlan *plan, const MStackMount *m) {
        assert(plan);
        assert(m);

        FOREACH_MSTACK_PLAN_LAYER(l, plan)
                if (l->mount == m)
                        return l;

        return NULL;
}

/* Works out the whole strategy up front, touching nothing. Runs before
 * mstack_back_synthetic_rw_layers() because it is what tells that pass which layers to back - not
 * because it has to observe them while they are still unbacked. */
int mstack_plan(MStack *mstack, MStackFlags flags, uid_t uid_shift, MStackPlan **ret) {
        assert(mstack);
        assert(ret);

        _cleanup_(mstack_plan_freep) MStackPlan *plan = new(MStackPlan, 1);
        if (!plan)
                return log_oom_debug();

        *plan = (MStackPlan) {
                .root_uid_shift = uid_shift,
                .extract_usr = mstack->extract_usr_only,
        };

        /* Mirrors mstack_realize_root(): a lone root/ is bound as-is, otherwise a tmpfs root if one was
         * asked for, otherwise whatever the overlay produced. */
        if (mstack->root_mount && !mstack->has_overlayfs)
                plan->shape = MSTACK_ROOT_SHAPE_BIND;
        else if (mstack->has_tmpfs_root)
                plan->shape = MSTACK_ROOT_SHAPE_TMPFS;
        else
                plan->shape = MSTACK_ROOT_SHAPE_OVERLAY;

        /* Whether the root takes MOUNT_ATTR_IDMAP itself, rather than inheriting it from layers idmapped
         * before merging - on an already-merged overlay it is refused with EINVAL. Nor for --volatile=yes,
         * which discards this root and keeps only a /usr/ clone that mstack_extract_usr() idmaps; a second
         * MOUNT_ATTR_IDMAP on that would be refused with EPERM. */
        plan->idmap_root_directly = plan->shape != MSTACK_ROOT_SHAPE_OVERLAY &&
                uid_is_valid(uid_shift) &&
                !mstack->extract_usr_only;

        FOREACH_MSTACK_LAYER(m, mstack) {
                if (!GREEDY_REALLOC(plan->layers, plan->n_layers + 1))
                        return log_oom_debug();

                bool writable = m->mount_type == MSTACK_RW && !mount_is_ro(mstack, m, flags);
                bool unbacked = m->synthetic;
                uid_t identity_uid = UID_INVALID;

                /* An unbacked rw/ layer is one --volatile=overlay conjured, and --volatile= never arrives
                 * with a tree-wide read-only request, so it is always the upper. Demoting it to a lower
                 * would leave it with no data/work and nothing to give it any, so refuse instead of
                 * assembling something that cannot work. */
                if (unbacked && !writable)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Refusing read-only mount stack with a synthetic writable layer: "
                                               "it has no backing of its own and nothing would supply one.");

                plan->layers[plan->n_layers++] = (MStackLayerPlan) {
                        .mount = m,
                        .role = !writable ? MSTACK_LAYER_ROLE_LOWER :
                                unbacked  ? MSTACK_LAYER_ROLE_UPPER_UNBACKED :
                                            MSTACK_LAYER_ROLE_UPPER,
                        .identity = mstack_layer_identity(mstack, uid_is_valid(uid_shift), writable, &identity_uid),
                        .identity_uid = identity_uid,
                };
        }

        *ret = TAKE_PTR(plan);
        return 0;
}

/* Appends one already-opened layer fd to the list the joined "lowerdir=" fallback will need. Takes
 * ownership of the fd, so callers hand it over with TAKE_FD() and the transfer stays visible at the call
 * site rather than hiding in here. */
static int mstack_overlay_builder_remember_lower(MStackOverlayBuilder *b, int fd) {
        assert(b);
        assert(fd >= 0);

        if (!GREEDY_REALLOC(b->lower_fds, b->n_lower_fds + 1))
                return log_oom_debug();

        b->lower_fds[b->n_lower_fds] = fd;
        b->n_lower_fds++;
        return 0;
}

/* Whatever its type, a prepared layer contributes to the overlay in exactly one of two ways: as another
 * read-only lower, or as the single writable upper - which the kernel wants as a data/work pair. These two
 * helpers are the two ways; which one a layer gets is decided in mstack_overlay_builder_add(). */
static int mstack_overlay_add_lower(MStackOverlayBuilder *b, const char *what, int fd) {
        int r;

        assert(b);
        assert(fd >= 0);

        r = fsconfig_add_layer(b->sb_fd, "lowerdir+", fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to set mount layer lowerdir+=%s: %m", strna(what));

        return mstack_overlay_builder_remember_lower(b, fd);
}

static int mstack_overlay_add_upper(MStackOverlayBuilder *b, const char *what, int data_fd, int work_fd) {
        int r;

        assert(b);
        assert(data_fd >= 0);
        assert(work_fd >= 0);

        /* rm_rf_children() takes possession of the fd no matter what, let's dup it here */
        int dup_fd = fcntl(work_fd, F_DUPFD_CLOEXEC, 3);
        if (dup_fd < 0)
                return log_debug_errno(errno, "Failed to duplicate work fd: %m");

        /* Empty the work directory, just in case it existed before. It's supposed to be empty. */
        r = rm_rf_children(dup_fd, REMOVE_PHYSICAL, /* root_dev= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to empty 'work' directory below 'rw' layer, ignoring: %m");

        r = fsconfig_add_layer(b->sb_fd, "upperdir", data_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to set mount layer upperdir=%s/data: %m", strna(what));

        r = fsconfig_add_layer(b->sb_fd, "workdir", work_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to set mount layer workdir=%s/work: %m", strna(what));

        b->upperdir_fd = data_fd;
        b->workdir_fd = work_fd;
        return 0;
}

/* Opens 'data'/'work' below an rw layer. Returns the fd, or a negative errno. */
static int mstack_overlay_open_subdir(int temp_fd, const char *name) {
        assert(temp_fd >= 0);
        assert(name);

        int fd = openat(temp_fd, name, O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open '%s' directory below 'rw' layer: %m", name);

        return fd;
}

/* Turns one layer into a mount the overlay can take, and hands it to the superblock in whichever role its
 * type calls for. */
static int mstack_overlay_builder_add(MStackMount *m, MStackOverlayBuilder *b) {
        int r;
        assert(m);
        assert(b);

        const MStackLayerPlan *lp = mstack_plan_find(b->plan, m);
        assert(lp);

        int source_fd = ASSERT_FD(mount_get_fd(m));
        bool rw_writable = mstack_layer_role_is_upper(lp->role);
        bool rw_readonly = m->mount_type == MSTACK_RW && !rw_writable;
        bool have_data_dir = true; /* an observation, not a decision - see below */

        /* Ensure 'data'/'work' exist (if needed) on the ORIGINAL source, before cloning it
         * below - not on the clone itself. Idmapped mounts (applied to the clone further
         * down) refuse further inode creation through them for a caller outside the mapped
         * range (EOVERFLOW - our own, unmapped credentials can't be represented as a
         * backing-store owner), and separately the kernel also refuses to idmap a mount that
         * has itself already had inodes created through that specific mount instance
         * (EINVAL) - so any creation has to happen on the pre-clone source, never on the
         * clone we're about to idmap. */
        if (rw_writable) {
                if (mkdirat(source_fd, "data", 0755) < 0 && errno != EEXIST)
                        return log_debug_errno(errno, "Failed to create 'data' on rw layer: %m");
                if (mkdirat(source_fd, "work", 0755) < 0 && errno != EEXIST)
                        return log_debug_errno(errno, "Failed to create 'work' on rw layer: %m");

                if (lp->identity == MSTACK_LAYER_IDENTITY_CHOWN) {
                        if (fchownat(source_fd, "data", lp->identity_uid, lp->identity_uid, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_debug_errno(errno, "Failed to chown 'data' on rw layer to " UID_FMT ": %m",
                                                       lp->identity_uid);
                        if (fchownat(source_fd, "work", lp->identity_uid, lp->identity_uid, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_debug_errno(errno, "Failed to chown 'work' on rw layer to " UID_FMT ": %m",
                                                       lp->identity_uid);
                }
        } else if (rw_readonly) {
                r = RET_NERRNO(faccessat(source_fd, "data", F_OK, 0));
                if (r == -ENOENT) /* If the 'data' dir doesn't exist, just skip over this
                                    * layer entirely, it apparently was never created, but
                                    * that's fine for a read-only invocation */
                        have_data_dir = false;
                else if (r < 0)
                        return log_debug_errno(r, "Failed to check for 'data' on read-only rw layer: %m");
        }

        /* overlayfs refuses to work with layers on mounts not owned by our userns, hence create a
         * clone that is owned by our userns */
        _cleanup_close_ int cloned_fd = mount_fd_clone(source_fd, /* recursive= */ false, /* replacement_fd= */ NULL);
        if (cloned_fd < 0)
                return log_debug_errno(cloned_fd, "Failed to clone mount for layer '%s': %m", strna(m->what));

        /* Idmap while the clone is still fresh and unattached, with nothing yet created through it:
         * that is the only point at which the kernel accepts MOUNT_ATTR_IDMAP for something destined
         * to become part of an overlay. Whether this layer wants it at all is
         * mstack_layer_identity()'s call. */
        if (lp->identity == MSTACK_LAYER_IDENTITY_IDMAP &&
            mount_setattr(cloned_fd, "", AT_EMPTY_PATH,
                          &(struct mount_attr) {
                                  .attr_set = MOUNT_ATTR_IDMAP,
                                  .userns_fd = b->uidmap_userns_fd,
                          }, sizeof(struct mount_attr)) < 0)
                return log_debug_errno(errno, "Failed to idmap layer '%s': %m", strna(m->what));

        /* See mstack_attach_temporarily(): overlayfs will not take a detached mount as upperdir. No
         * matching detach here - we are in a forked child with its own mount namespace, which takes the
         * attachment with it when it exits. */
        r = mstack_attach_temporarily(cloned_fd, b->temp_mount_dir);
        if (r < 0)
                return r;

        /* Open the layer immediately after attaching */
        _cleanup_close_ int temp_fd = open(b->temp_mount_dir, O_PATH|O_CLOEXEC);
        if (temp_fd < 0)
                return log_debug_errno(errno, "Failed to open attached layer '%s': %m", b->temp_mount_dir);

        if (m->mount_type != MSTACK_RW) {
                /* root/ sorts before every layer@ (MSTACK_ROOT is the lowest mount type), so it is
                 * processed last in the caller's reverse loop and naturally ends up as the bottommost
                 * lowerdir: the base that layer@/rw sit on top of, across the whole tree rather than
                 * just /usr/. */
                return mstack_overlay_add_lower(b, m->what, TAKE_FD(temp_fd));
        }

        if (rw_readonly) {
                if (!have_data_dir)
                        return 0;

                /* Downgrade to a regular lowerdir if read-only is requested */
                _cleanup_close_ int ro_data_fd = mstack_overlay_open_subdir(temp_fd, "data");
                if (ro_data_fd < 0)
                        return ro_data_fd;

                return mstack_overlay_add_lower(b, m->what, TAKE_FD(ro_data_fd));
        }

        /* 'data'/'work' were already created (if missing) on the pre-clone source above, so just open
         * them here. */
        _cleanup_close_ int data_fd = mstack_overlay_open_subdir(temp_fd, "data");
        if (data_fd < 0)
                return data_fd;

        _cleanup_close_ int work_fd = mstack_overlay_open_subdir(temp_fd, "work");
        if (work_fd < 0)
                return work_fd;

        return mstack_overlay_add_upper(b, m->what, TAKE_FD(data_fd), TAKE_FD(work_fd));
}

/* Turns the whole stack into a realized overlayfs superblock. Split out so it can run either inside the
 * forked mount namespace child or, where the kernel does not need one, directly. */
static int mstack_overlay_assemble(
                MStack *mstack,
                const MStackPlan *plan,
                const char *temp_mount_dir,
                int uidmap_userns_fd,
                int sb_fd,
                int sb_fd_fallback,
                bool writable) {

        int r;

        assert(mstack);
        assert(plan);
        assert(temp_mount_dir);
        assert(sb_fd >= 0);
        assert(sb_fd_fallback >= 0);

        _cleanup_(mstack_overlay_builder_done) MStackOverlayBuilder builder = {
                .sb_fd = sb_fd,
                .temp_mount_dir = temp_mount_dir,
                .uidmap_userns_fd = uidmap_userns_fd,
                .plan = plan,
                .upperdir_fd = -EBADF,
                .workdir_fd = -EBADF,
        };

        FOREACH_MSTACK_LAYER_TOP_DOWN(m, mstack) {
                r = mstack_overlay_builder_add(m, &builder);
                if (r < 0)
                        return r;
        }

        r = mstack_overlayfs_create(sb_fd, writable, empty_to_root(mstack->path));
        if (r == -EINVAL && builder.n_lower_fds > 0) {
                log_debug_errno(r, "Failed to realize overlayfs via incremental 'lowerdir+', retrying with a single joined 'lowerdir=': %m");

                _cleanup_strv_free_ char **lower_paths = NULL;
                FOREACH_ARRAY(fd, builder.lower_fds, builder.n_lower_fds)
                        if (strv_extend(&lower_paths, FORMAT_PROC_FD_PATH(*fd)) < 0)
                                return log_oom_debug();

                _cleanup_free_ char *joined = strv_join(lower_paths, ":");
                if (!joined)
                        return log_oom_debug();

                if (fsconfig(sb_fd_fallback, FSCONFIG_SET_STRING, "lowerdir", joined, /* aux= */ 0) < 0)
                        return log_debug_errno(errno, "Failed to configure the fallback overlayfs: %m");

                if (builder.upperdir_fd >= 0 &&
                    fsconfig(sb_fd_fallback, FSCONFIG_SET_STRING, "upperdir", FORMAT_PROC_FD_PATH(builder.upperdir_fd), /* aux= */ 0) < 0)
                        return log_debug_errno(errno, "Failed to configure the fallback overlayfs: %m");

                if (builder.workdir_fd >= 0 &&
                    fsconfig(sb_fd_fallback, FSCONFIG_SET_STRING, "workdir", FORMAT_PROC_FD_PATH(builder.workdir_fd), /* aux= */ 0) < 0)
                        return log_debug_errno(errno, "Failed to configure the fallback overlayfs: %m");

                r = mstack_overlayfs_create(sb_fd_fallback, writable, empty_to_root(mstack->path));
        }

        return r;
}

static int mstack_make_overlayfs(
                MStack *mstack,
                const MStackPlan *plan,
                const char *temp_mount_dir,
                MStackFlags flags,
                uid_t uid_shift,
                int *ret_overlayfs_mnt_fd) {

        int r;

        assert(mstack);
        assert(plan);
        assert(temp_mount_dir);
        assert(ret_overlayfs_mnt_fd);

        if (!mstack->has_overlayfs) {
                *ret_overlayfs_mnt_fd = -EBADF;
                return 0;
        }

        bool writable = mstack_has_writable_layers(mstack, flags);

        /* Warm the capability cache here, in the parent. The layer loop below runs inside a forked child,
         * and anything probed there is cached in a process that is about to exit - so leaving it to be
         * probed on first use would re-probe on every assembly rather than once per process. */
        (void) mstack_caps();

        /* overlayfs cannot itself be the target of an idmapped mount (mount_setattr(MOUNT_ATTR_IDMAP) on an
         * already-merged overlay returns EINVAL) - the kernel only supports idmapping the individual layers
         * that go INTO an overlay, before they're merged. So if an idmap was requested, acquire the userns
         * once here and apply it to each layer's cloned mount fd below, before it's merged; the assembled
         * overlay then inherits the mapping from its already-idmapped layers. */
        _cleanup_close_ int uidmap_userns_fd = -EBADF;
        if (uid_is_valid(uid_shift)) {
                uidmap_userns_fd = mstack_make_userns(mstack, uid_shift);
                if (uidmap_userns_fd < 0)
                        return log_debug_errno(uidmap_userns_fd, "Failed to create idmap userns: %m");
        }

        _cleanup_close_ int sb_fd = fsopen("overlay", FSOPEN_CLOEXEC);
        if (sb_fd < 0)
                return log_debug_errno(errno, "Failed to create overlayfs: %m");

        /* Some kernels only partially back-port overlayfs's fs_context-based incremental "lowerdir+"
         * layer scheme (mainlined in Linux 6.5): every individual fsconfig() call to add a layer via
         * "lowerdir+" succeeds, yet FSCONFIG_CMD_CREATE still fails with EINVAL. A bare retry on the
         * same fs_context after that returns EBUSY, so a genuinely fresh superblock is needed - and
         * since fds opened by the child below after fork() aren't visible to us afterwards, it has to
         * be opened here, before forking, so it's shared with the child exactly like the one above. */
        _cleanup_close_ int sb_fd_fallback = fsopen("overlay", FSOPEN_CLOEXEC);
        if (sb_fd_fallback < 0)
                return log_debug_errno(errno, "Failed to create fallback overlayfs: %m");

        _cleanup_close_pair_ int errno_pipe_fds[2] = EBADF_PAIR;
        if (pipe2(errno_pipe_fds, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to open pipe: %m");

        /* The layers have to be attached somewhere before overlayfs will take them, so fork off a child
         * with a private mount namespace and do it there, where no one else sees it. */
        r = pidref_safe_fork("(layerfd)",
                      FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                      /* ret= */ NULL);
        if (r < 0) {
                errno_pipe_fds[1] = safe_close(errno_pipe_fds[1]);

                int q = read_errno(errno_pipe_fds[0]);
                if (q < 0 && q != -EIO)
                        return q;

                return r;
        }
        if (r == 0) {
                /* child */
                r = mstack_overlay_assemble(mstack, plan, temp_mount_dir, uidmap_userns_fd,
                                            sb_fd, sb_fd_fallback, writable);
                report_errno_and_exit(errno_pipe_fds[1], r);
        }

        /* The child above realizes whichever of the two superblocks actually worked (see the
         * "lowerdir+" EINVAL fallback there); try the primary one first, then the fallback. */
        _cleanup_close_ int overlayfs_mnt_fd = fsmount(sb_fd, FSMOUNT_CLOEXEC, 0);
        if (overlayfs_mnt_fd < 0)
                overlayfs_mnt_fd = fsmount(sb_fd_fallback, FSMOUNT_CLOEXEC, 0);
        if (overlayfs_mnt_fd < 0)
                return log_debug_errno(errno, "Failed to create mount fd: %m");

        if (mount_setattr(overlayfs_mnt_fd, "", AT_EMPTY_PATH,
                          &(struct mount_attr) {
                                  .attr_set = writable ? 0 : MOUNT_ATTR_RDONLY,
                                  .attr_clr = writable ? MOUNT_ATTR_RDONLY : 0,
                          }, sizeof(struct mount_attr)) < 0)
                return log_debug_errno(errno, "Failed to mark root bind mount read-only: %m");

        *ret_overlayfs_mnt_fd = TAKE_FD(overlayfs_mnt_fd);
        return 1;
}

/* A synthetic 'rw' layer - one nspawn conjured for --volatile=overlay rather than one the caller put on
 * disk - has no backing of its own. Give it a throwaway tmpfs to hold its 'data'/'work' before the overlay
 * is assembled. */
static int mstack_back_synthetic_rw_layers(MStack *mstack, const MStackPlan *plan) {
        int r;

        assert(mstack);
        assert(plan);

        FOREACH_MSTACK_PLAN_LAYER(l, plan) {
                if (l->role != MSTACK_LAYER_ROLE_UPPER_UNBACKED)
                        continue;

                r = mstack_make_tmpfs(mstack, TMPFS_LIMITS_ROOTFS, &l->mount->mount_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create tmpfs backing for synthetic rw layer: %m");
        }

        return 0;
}

/* Produces the tree that will become the container's root, as a still-detached mount fd on
 * mstack->root_mount_fd. Which of the three shapes it takes - a merged overlay, a bind of a lone root/, or
 * a throwaway tmpfs - follows from what the stack contains. */
static int mstack_realize_root(
                MStack *mstack,
                const MStackPlan *plan,
                const char *temp_mount_dir,
                MStackFlags flags,
                uid_t uid_shift) {

        int r;

        assert(mstack);
        assert(plan);
        assert(temp_mount_dir);

        _cleanup_close_ int overlayfs_mnt_fd = -EBADF;
        r = mstack_make_overlayfs(mstack, plan, temp_mount_dir, flags, uid_shift, &overlayfs_mnt_fd);
        if (r < 0)
                return r;
        if (r > 0)
                log_debug("Acquired mstack overlayfs mount.");

        assert(mstack->root_mount_fd < 0);

        if (plan->shape == MSTACK_ROOT_SHAPE_BIND) {
                /* If there's also an overlay (layer@/rw), root/ was already folded into it as the base
                 * lowerdir by mstack_make_overlayfs() above, so the overlay fd itself becomes our root
                 * below; there's nothing further to do for root/ here in that case. */
                assert(!mstack->has_tmpfs_root);

                mstack->root_mount_fd = fcntl(mount_get_fd(mstack->root_mount), F_DUPFD_CLOEXEC, 3);
                if (mstack->root_mount_fd < 0)
                        return log_debug_errno(errno, "Failed to create root bind mount: %m");

                log_debug("Acquired mstack root bind mount.");

        } else if (plan->shape == MSTACK_ROOT_SHAPE_TMPFS) {
                r = mstack_make_tmpfs(mstack, TMPFS_LIMITS_ROOTFS, &mstack->root_mount_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create root tmpfs: %m");

                log_debug("Acquired root tmpfs mount.");
        }

        /* If we acquired no other root fs (or root/ was folded into the overlay above as its base layer),
         * then the overlayfs is our root */
        if (plan->shape == MSTACK_ROOT_SHAPE_OVERLAY)
                mstack->root_mount_fd = TAKE_FD(overlayfs_mnt_fd);
        else if (plan->idmap_root_directly) {

                /* Unlike the overlay case above (already idmapped layer-by-layer before merging), this is a
                 * plain, single, not-yet-attached mount (a bind of root/ alone, or a throwaway tmpfs) -
                 * regular filesystems ARE a valid target for MOUNT_ATTR_IDMAP directly.
                 *
                 * Skipped for --volatile=yes (extract_usr_only): that mode throws this root away below and
                 * replaces it with a fresh tmpfs, keeping only a clone of /usr/ - which is idmapped there,
                 * separately. Idmapping here first would mean cloning /usr/ out of an already-idmapped
                 * mount, and the kernel refuses to apply a second MOUNT_ATTR_IDMAP to it (EPERM). */
                _cleanup_close_ int userns_fd = mstack_make_userns(mstack, uid_shift);
                if (userns_fd < 0)
                        return log_debug_errno(userns_fd, "Failed to create idmap userns: %m");

                if (mount_setattr(mstack->root_mount_fd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = MOUNT_ATTR_IDMAP,
                                          .userns_fd = userns_fd,
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_debug_errno(errno, "Failed to idmap root mount: %m");
        }

        return 0;
}

/* --volatile=yes keeps nothing but /usr/, so the tree has to be one where that is enough to boot: /bin (and
 * with it /sbin, /lib, /lib64) must either not exist yet, or already be a symlink into /usr/. A real /bin
 * directory means the image never adopted the merged-/usr scheme. */
static int mstack_verify_merged_usr(int root_fd) {
        assert(root_fd >= 0);

        /* The two messages below stay at error level, against the usual rule that src/shared/ leaves
         * logging to its caller, for the same reason as the one in mstack_open_mount_point(): they are
         * actionable guidance the caller cannot reconstruct from the bare EISDIR/EINVAL it receives, and
         * they were user-visible here before this code moved out of nspawn. */
        struct stat st;
        if (fstatat(root_fd, "bin", &st, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to stat /bin below --volatile=yes root: %m");
        } else if (S_ISDIR(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EISDIR),
                                       "Sorry, --volatile=yes mode is not supported with OS images that have not merged /bin/, /sbin/, /lib/, /lib64/ into /usr/. "
                                       "Please work with your distribution and help them adopt the merged /usr scheme.");
        else if (!S_ISLNK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "If --volatile=yes is used /bin must be a symlink (for merged /usr support) or non-existent "
                                       "(in which case a symlink is created automatically).");

        return 0;
}

/* Clones /usr/ out of the assembled tree and then throws the tree itself away, replacing it with a fresh
 * tmpfs - which is what --volatile=yes means. */
static int mstack_extract_usr(MStack *mstack, const char *temp_mount_dir, uid_t uid_shift) {
        int r;

        assert(mstack);
        assert(temp_mount_dir);

        /* We now have a fully assembled tree at root_mount_fd (whatever combination of root/,
         * layer@, rw/ that represents); clone /usr/ out of it before replacing root_mount_fd
         * itself with a throwaway tmpfs. open_tree(OPEN_TREE_CLONE) refuses a subdirectory of a
         * still-detached mount - see mstack_attach_temporarily(), which is the same restriction
         * mstack_make_overlayfs() has to work around. Attach root_mount_fd first, so usr/ becomes
         * a real, resolvable path, then detach again immediately after. Unlike the overlayfs case
         * we are in the caller's own mount namespace here, so the detach is ours to do, on every
         * path out. mstack_bind_mounts() re-attaches root_mount_fd to this same directory for real
         * once assembly is complete, so nothing is lost by round-tripping through it here. */
        /* Built before the attach: it is pure string work, so a failure here has nothing to detach. */
        _cleanup_free_ char *temp_usr_dir = path_join(temp_mount_dir, "usr");
        if (!temp_usr_dir)
                return log_oom_debug();

        r = mstack_attach_temporarily(mstack->root_mount_fd, temp_mount_dir);
        if (r < 0)
                return r;

        /* AT_RECURSIVE for the same reason nspawn's own clone of the root uses it: the prepared tree may
         * already carry mounts below /usr/ - a separately mounted /usr/local, a nested subvolume - and a
         * non-recursive clone would drop them here, leaving empty mountpoint directories in the volatile
         * root. That would also undo, one step later, exactly what that clone took care to preserve. The
         * kernel refuses a recursive clone outright when the subtree holds a locked or unbindable mount,
         * so fall back the same way rather than failing --volatile=yes over it. */
        mstack->usr_extract_fd = open_tree(AT_FDCWD, temp_usr_dir,
                                           OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_RECURSIVE|AT_SYMLINK_NOFOLLOW);
        if (mstack->usr_extract_fd < 0 && errno == EINVAL) {
                log_debug("Recursive clone of '/usr/' refused (locked or unbindable submounts?), falling back "
                          "to non-recursive; nested submounts below /usr/ will not be preserved.");
                mstack->usr_extract_fd = open_tree(AT_FDCWD, temp_usr_dir,
                                                   OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW);
        }

        /* Detach on every path out, without letting the detach itself clobber the errno we report. */
        {
                PROTECT_ERRNO;
                (void) umount2(temp_mount_dir, MNT_DETACH);
        }

        if (mstack->usr_extract_fd < 0)
                return log_debug_errno(errno, "Failed to clone /usr/ for --volatile=yes: %m");

        /* Idmap usr_extract_fd here, while it's still a fresh, unattached clone with nothing yet
         * created through it - same reasoning as the per-layer idmap in mstack_make_overlayfs()
         * above: this is the only point at which the kernel allows MOUNT_ATTR_IDMAP on it. This
         * matters for --directory=/--image= + --volatile=yes with a non-managed userns
         * (nspawn.c's synthetic MStack wrapping passes tmpfs_uid_shift = chown_uid there, unlike
         * the plain --mstack= case which always passes UID_INVALID): nspawn's own separate
         * remount_idmap() step further up its call chain used to idmap this same path afterward,
         * but by then it's already the merged overlay assembled here, and the kernel refuses to
         * idmap an already-merged overlay - so it must happen here instead, before merging is
         * even a concept that applies (usr_extract_fd is just a detached clone, not yet attached
         * anywhere). nspawn.c is expected to skip its own remount_idmap() pass for this path once
         * this has already applied it. */

        /* When an overlay was assembled, mstack_make_overlayfs() already idmapped each layer
         * individually with uid_shift, and the clone we just took inherits that mapping - applying
         * a second one here would either be refused outright or shift ownership twice. No caller
         * combines a valid uid_shift with layers today (the paths that pass one always wrap a
         * single root), but nothing enforces that pairing, so don't rely on it. */
        _cleanup_close_ int usr_idmap_userns_fd = -EBADF;
        if (uid_is_valid(uid_shift) && mstack->has_overlayfs)
                log_debug("Overlay layers were already idmapped, not remapping the extracted /usr/.");
        else if (uid_is_valid(mstack->tmpfs_uid_shift)) {
                usr_idmap_userns_fd = mstack_make_userns(mstack, mstack->tmpfs_uid_shift);
                if (usr_idmap_userns_fd < 0)
                        return log_debug_errno(usr_idmap_userns_fd, "Failed to create idmap userns for /usr/: %m");
        }

        if (mount_setattr(mstack->usr_extract_fd, "", AT_EMPTY_PATH,
                          &(struct mount_attr) {
                                  .attr_set = MOUNT_ATTR_RDONLY | (usr_idmap_userns_fd >= 0 ? MOUNT_ATTR_IDMAP : 0),
                                  .propagation = MS_PRIVATE, /* disconnect us from bind mount source */
                                  .userns_fd = usr_idmap_userns_fd,
                          }, sizeof(struct mount_attr)) < 0)
                return log_debug_errno(errno, "Failed to mark /usr/ read-only for --volatile=yes: %m");

        mstack->root_mount_fd = safe_close(mstack->root_mount_fd);
        r = mstack_make_tmpfs(mstack, TMPFS_LIMITS_ROOTFS, &mstack->root_mount_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to create throwaway root tmpfs for --volatile=yes: %m");

        /* If there was an explicit root/ entry, it's now fully consumed: its content only lives
         * on in usr_extract_fd, and root_mount_fd is a throwaway tmpfs that has nothing to do
         * with it any more. Clear the stale pointer so mstack_bind_mounts()'s root_writable check
         * correctly takes the "throwaway tmpfs, stay writable" branch instead of the "protect the
         * real root/ entry" one - otherwise the fresh tmpfs would incorrectly end up read-only
         * (mstack_has_writable_layers() is false for --volatile=yes, there's no rw/ layer),
         * breaking base_filesystem_create() and friends immediately afterwards. */
        mstack->root_mount = NULL;

        /* Likewise, whatever overlay was assembled has been consumed into usr_extract_fd: the tree
         * we are left holding is a plain tmpfs. Keep the struct honest for later readers. */
        mstack->has_overlayfs = false;

        log_debug("Extracted /usr/ for --volatile=yes, replaced root with a throwaway tmpfs.");

        return 0;
}

int mstack_make_mounts(
                MStack *mstack,
                const char *temp_mount_dir,
                MStackFlags flags,
                uid_t uid_shift) {

        int r;

        assert(mstack);
        assert(temp_mount_dir);

        /* Decide everything first, while nothing is mounted yet and the entries still say what the
         * caller configured rather than what assembly has done to them. */
        _cleanup_(mstack_plan_freep) MStackPlan *plan = NULL;
        r = mstack_plan(mstack, flags, uid_shift, &plan);
        if (r < 0)
                return r;

        r = mstack_back_synthetic_rw_layers(mstack, plan);
        if (r < 0)
                return r;

        /* From here on the plan is the source of truth, uid_shift included - so there is one value
         * rather than a parameter travelling alongside a field that records the same thing. */
        r = mstack_realize_root(mstack, plan, temp_mount_dir, flags, plan->root_uid_shift);
        if (r < 0)
                return r;

        if (plan->extract_usr) {
                r = mstack_verify_merged_usr(mstack->root_mount_fd);
                if (r < 0)
                        return r;

                r = mstack_extract_usr(mstack, temp_mount_dir, plan->root_uid_shift);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Applies the read-only/writable attribute a mount should end up with, given its type and the caller's
 * flags. Shared by every attach path, so the answer is derived in one place rather than at each. */
static int mstack_apply_attr(
                int dfd,
                MStackMountType mount_type,
                bool writable,
                MStackFlags flags,
                bool root_recursive_ok) {

        /* ROBIND is always read-only.
         * ROOT is read-only if writable is false (due to MSTACK_RDONLY or no write layers).
         * BIND is read-only either because MSTACK_RDONLY makes the whole tree read-only, or because
         * MSTACK_BINDS_RDONLY singles the caller's binds out in the cases where the root itself has to
         * stay writable. */
        bool rdonly = mount_type == MSTACK_ROBIND ||
                      (mount_type == MSTACK_ROOT && !writable) ||
                      (mount_type == MSTACK_BIND && (flags & (MSTACK_RDONLY|MSTACK_BINDS_RDONLY)));

        /* Non-ROOT mount types (bind@/robind@/tmpfs@) always recurse: they're freshly attached,
         * single-purpose mounts with nothing else layered inside them yet.
         *
         * For ROOT, the caller decides via root_recursive_ok: recursing is only safe once nothing else
         * is already attached under root that a recursive attribute change would incorrectly clobber -
         * bind@/robind@ mounts (attached earlier when not MSTACK_DEFER_MOUNT, see
         * mstack_apply_bind_mounts() above) or the /usr/ extracted by --volatile=yes (attached earlier
         * unconditionally, see mstack_bind_mounts() above, regardless of MSTACK_DEFER_MOUNT). When it
         * genuinely is safe (MSTACK_DEFER_MOUNT, no --volatile=yes extraction), recursing here is in fact
         * needed: it's the only way nested submounts that were part of the original --directory=/--image=
         * tree itself (preserved by nspawn.c's own AT_RECURSIVE clone) inherit root's read-only/writable
         * state, matching what the pre-mstack setup_volatile_state() did via its own
         * bind_remount_recursive() call. */
        bool recursive = mount_type != MSTACK_ROOT || root_recursive_ok;
        int attr_flags = AT_EMPTY_PATH | (recursive ? AT_RECURSIVE : 0);

        struct mount_attr ma = {
                .attr_set = rdonly ? MOUNT_ATTR_RDONLY : 0,
                /* Never clear read-only while MSTACK_RDONLY is in effect: mstack_open_images() already
                 * set MOUNT_ATTR_RDONLY on every entry's fd (mount_is_ro() is unconditionally true
                 * then), so clearing it here - recursively, at that - would silently undo the caller's
                 * read-only request, down into submounts nested inside a bind source. */
                .attr_clr = !rdonly && !FLAGS_SET(flags, MSTACK_RDONLY) ? MOUNT_ATTR_RDONLY : 0,
        };

        if (mount_setattr(dfd, "", attr_flags, &ma, sizeof(ma)) < 0) {
                if (errno != EINVAL || !recursive)
                        return log_debug_errno(errno, "Failed to set mount attributes: %m");

                /* A recursive attribute change can fail with EINVAL if the subtree contains a locked
                 * mount somewhere (same class of restriction the AT_RECURSIVE clone in nspawn.c already
                 * has an identical fallback for). Falling back to a non-recursive change is only
                 * acceptable in the direction that cannot weaken anything: when we are *clearing*
                 * read-only, submounts we failed to reach simply stay read-only. In the other direction
                 * the fallback would leave every nested submount writable while the caller believes the
                 * tree is read-only - and the contents of an untrusted image would get to decide that.
                 * Both predecessors failed hard there (base mstack_bind_mounts() and the
                 * setup_volatile_state() it replaces), so do the same.
                 *
                 * Reported at error level for the same reason as the EBUSY in mstack_overlayfs_create():
                 * the caller receives a bare EINVAL and renders "Invalid argument", which says nothing
                 * about what to do. That a locked submount inside this subtree is what refused, and that
                 * the alternative would have been to hand back a tree only partly read-only, is knowable
                 * only here. */
                if (rdonly)
                        return log_error_errno(errno,
                                               "Failed to make %s mount recursively read-only: a locked or unbindable "
                                               "submount inside it cannot be changed. Refusing rather than handing back a "
                                               "tree that is only partly read-only: %m",
                                               strna(mstack_mount_type_to_string(mount_type)));

                log_debug_errno(errno, "Failed to recursively set mount attributes, falling back to non-recursive: %m");
                if (mount_setattr(dfd, "", AT_EMPTY_PATH, &ma, sizeof(ma)) < 0)
                        return log_debug_errno(errno, "Failed to set mount attributes: %m");
        }

        return 0;
}

static int mstack_apply_propagation(int dfd) {
        if (mount_setattr(dfd, "", AT_EMPTY_PATH|AT_RECURSIVE,
                          &(struct mount_attr) {
                                  .propagation = MS_SHARED,
                          }, sizeof(struct mount_attr)) < 0)
                return log_debug_errno(errno, "Failed to set mount propagation: %m");

        return 0;
}

/* Resolves - creating it if necessary - the directory an overmount entry is to be attached to.
 *
 * Tries a strict resolution first, so that for a path with no symlink in it the entry provably lands
 * exactly where the .mstack/ author named it, and nothing the image ships can move it.
 *
 * Symlinks do have to be followed, though: images ship compatibility symlinks in the middle of the
 * paths entries are written against (/var/run -> /run on anything merged-/usr, and the well-known
 * locations below it), so refusing would make those targets unexpressible.
 *
 * What the relaxation costs is that the image, rather than the entry, picks the final location. It
 * cannot pick one outside the container: chaseat() resolves everything against root_fd, so an absolute
 * symlink means absolute-within-the-root and there is no escape. But it can redirect within the root,
 * so the resolved path is logged rather than followed silently. */
static int mstack_open_mount_point(int root_fd, const char *where, int *ret_fd) {
        int r;

        assert(root_fd >= 0);
        assert(where);
        assert(ret_fd);

        _cleanup_close_ int subdir_fd = -EBADF;
        r = chaseat(root_fd, root_fd, where,
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                    /* ret_path= */ NULL, &subdir_fd);
        if (IN_SET(r, -ELOOP, -EREMCHG)) {
                _cleanup_free_ char *resolved = NULL;

                r = chaseat(root_fd, root_fd, where,
                            CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                            &resolved, &subdir_fd);
                if (r >= 0)
                        log_debug("Mount target '%s' resolves through a symlink to '%s'; attaching it there.",
                                  where, resolved);
        }
        /* Logged at error level on purpose, against the usual rule that src/shared/ leaves the logging
         * to its caller: this is actionable guidance the caller cannot reconstruct. All it sees is
         * EROFS, so it reports "Read-only file system" for a situation whose fix - add an rw/ layer -
         * is only knowable here. TEST-13-NSPAWN.mstack.sh asserts this reaches the user. */
        if (r == -EROFS)
                return log_error_errno(r, "Failed to create mount point directory '%s': root is read-only. "
                                       "Add an rw/ directory to the .mstack/, use --volatile= to provide a writable root layer, "
                                       "or pre-create the bind target directory in the base layer: %m", where);
        if (r < 0)
                return log_debug_errno(r, "Failed to open mount point inode '%s': %m", where);

        *ret_fd = TAKE_FD(subdir_fd);
        return 0;
}

/* Attaches one phase's worth of bind@/robind@/tmpfs@ entries. With 'volatile_only' the entries
 * mstack_merge_volatile() synthesized are attached (during assembly, while the root is still being put
 * together); without it the caller's own entries are, which is what the deferred post-API-VFS pass does.
 * The two sets are disjoint, so neither phase ever attaches anything twice.
 *
 * Deliberately not exported: the phase selector and the already-open root_fd are easy to get wrong from
 * outside, and every external caller wants mstack_apply_bind_mounts_late() instead. */
static int mstack_apply_bind_mounts(
                MStack *mstack,
                int root_fd,
                const char *where,
                MStackFlags flags,
                bool volatile_only) {

        int r;

        assert(mstack);
        assert(root_fd >= 0);
        assert(where);

        bool writable = mstack_has_writable_layers(mstack, flags);

        FOREACH_MSTACK_OVERMOUNT(m, mstack) {
                if (m == mstack->root_mount)
                        continue;

                /* Each entry belongs to exactly one phase: volatile-derived entries go up during assembly,
                 * everything else in the deferred pass. */
                if (m->from_volatile != volatile_only)
                        continue;

                /* Bind/robind mounts have their fd pre-made in mstack_make_mounts(); a tmpfs submount is
                 * created fresh here. Either way 'mount_fd' below is what we attach. */
                _cleanup_close_ int tmpfs_fd = -EBADF;
                if (m->mount_type == MSTACK_TMPFS) {
                        r = mstack_make_tmpfs(mstack, TMPFS_LIMITS_VOLATILE_STATE, &tmpfs_fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to create tmpfs for '%s': %m", m->where);
                } else
                        assert(m->mount_fd >= 0);

                int mount_fd = m->mount_type == MSTACK_TMPFS ? tmpfs_fd : m->mount_fd;

                _cleanup_close_ int subdir_fd = -EBADF;
                r = mstack_open_mount_point(root_fd, m->where, &subdir_fd);
                if (r < 0)
                        return r;

                if (move_mount(mount_fd, "", subdir_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                        return log_debug_errno(errno, "Failed to attach bind mount to '%s' subdir: %m", m->where);

                /* Set mount attributes on each mount fd after attaching it. This is the only place they
                 * are set, on every path: the root's own attribute pass in mstack_bind_mounts() recurses
                 * only when nothing is attached underneath it yet (see root_recursive_ok there), which by
                 * definition does not hold for the mounts attached here - whether that happens
                 * immediately, or later from mstack_apply_bind_mounts_late() after mount_all(). */
                r = mstack_apply_attr(mount_fd, m->mount_type, writable, flags, /* root_recursive_ok= */ false);
                if (r < 0)
                        return r;

                r = mstack_apply_propagation(mount_fd);
                if (r < 0)
                        return r;

                log_debug("Attached mstack '%s/' mount to '%s%s/'.", m->where, where, m->where);
        }

        return 0;
}

int mstack_apply_bind_mounts_late(MStack *mstack, const char *where, MStackFlags flags) {
        int r;

        assert(mstack);
        assert(where);

        /* The caller's own bind@/robind@/tmpfs@ entries go up here, after the caller has mounted whatever
         * it mounts of its own - nspawn's mount_all(), the service manager's apply_mounts() - because
         * those establish fresh API VFS filesystems (/proc, /dev, /run, /tmp, /sys) that would otherwise
         * shadow any entry at the same path. The entries mstack_merge_volatile() synthesizes are the
         * exception: they are marked from_volatile and went up during assembly, since they only target
         * paths the root itself owns (/var/) and have nothing here that could shadow them.
         *
         * Open an O_PATH fd anchored to the staged root so that mstack_apply_bind_mounts() can resolve
         * bind targets relative to it with chaseat(), without symlink escape risk. */
        _cleanup_close_ int root_fd = open(where, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0)
                return log_debug_errno(errno, "Failed to open root '%s' for mstack bind mounts: %m", where);

        r = mstack_apply_bind_mounts(mstack, root_fd, where, flags, /* volatile_only= */ false);
        if (r < 0)
                return r;

        log_debug("Applied .mstack bind mounts.");
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

        bool writable = mstack_has_writable_layers(mstack, flags);

        _cleanup_close_ int _where_fd = -EBADF;
        if (where_fd == AT_FDCWD) {
                _where_fd = open(".", O_CLOEXEC|O_PATH|O_DIRECTORY);
                if (_where_fd < 0)
                        return log_debug_errno(errno, "Failed to open current working directory: %m");
                where_fd = _where_fd;
        } else if (where_fd < 0) {
                r = chase(where,
                          /* root= */ NULL,
                          (FLAGS_SET(flags, MSTACK_MKDIR) ? CHASE_MKDIR_0755 : 0)|CHASE_MUST_BE_DIRECTORY,
                          /* ret_path= */ NULL,
                          &_where_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to open '%s': %m", where);

                where_fd = _where_fd;
        }

        /* Not an assert: the root fd is dropped once it has been attached below, so a second call would
         * trip it. Report that rather than aborting. */
        if (mstack->root_mount_fd < 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Mount stack has no root mount to attach; was it assembled, or already attached?");

        if (move_mount(mstack->root_mount_fd, "", where_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                return log_debug_errno(errno, "Failed to attach mstack root mount to '%s': %m", where);

        log_debug("Attached mstack root mount to '%s'.", where);

        /* The mount is now reachable by path via 'where' - drop the fds that still reference the
         * underlying mount (root_mount_fd, and the MSTACK_ROOT entry's own mount_fd it may have been
         * duplicated from in mstack_make_mounts()). A non-lazy umount2() of 'where' (e.g. nspawn's own
         * remount_idmap()) refuses with EBUSY while either fd remains open, even with nothing else
         * actually using the mount. Nothing past this point needs them: the deferred bind@/tmpfs@ pass
         * (mstack_apply_bind_mounts(), possibly much later) re-derives its own fd from the path instead. */
        mstack->root_mount_fd = safe_close(mstack->root_mount_fd);
        if (mstack->root_mount) {
                mstack->root_mount->mount_fd = safe_close(mstack->root_mount->mount_fd);
                mstack->root_mount->fd_consumed = true;
        }

        _cleanup_close_ int root_fd = open(where, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0)
                return log_debug_errno(errno, "Failed to mount root mount '%s': %m", where);

        /* Remembered separately from the fd, which is dropped again as soon as the mount is attached below:
         * the root attribute pass further down must know whether a /usr/ is sitting under the root, and
         * must not learn that from whether we still happen to hold a handle on it. */
        bool attached_usr = mstack->usr_extract_fd >= 0;

        if (mstack->usr_extract_fd >= 0) {
                /* --volatile=yes: attach the /usr/ extracted by mstack_make_mounts() now, early (same
                 * timing as the root mount above, well before the caller's own idmap remount step, if
                 * any) - a plain bind entry would only be attached in the deferred pass below, too late
                 * for that idmap step to see and correctly map /usr/. */
                _cleanup_close_ int subdir_fd = -EBADF;
                r = chaseat(root_fd, root_fd, "usr", CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &subdir_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to open mount point inode '%s/usr': %m", where);

                if (move_mount(mstack->usr_extract_fd, "", subdir_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                        return log_debug_errno(errno, "Failed to attach extracted /usr/ to '%s/usr': %m", where);

                /* Same rule as the root mount above: once attached, the mount is reachable by path and the
                 * fd is only a liability. Holding it keeps a reference that makes a later non-lazy
                 * umount2() of '<where>/usr' fail with EBUSY - which is exactly what nspawn's
                 * remount_idmap() pass does when an --image= carries a separate /usr partition. */
                mstack->usr_extract_fd = safe_close(mstack->usr_extract_fd);

                log_debug("Attached extracted /usr/ to '%s/usr/'.", where);
        }

        /* Pre-create every mount target while the root is still writable - the root is made read-only just
         * below, and both the deferred pass (after mount_all(), much later) and the volatile pass (right
         * after that, still here) would otherwise be unable to create a missing target directory.
         * Directories under paths that mount_all() replaces (e.g. /run, /tmp) will be hidden, but the
         * deferred apply recreates them on the new writable mounts. */
        FOREACH_MSTACK_OVERMOUNT(m, mstack) {
                if (m == mstack->root_mount)
                        continue;

                _cleanup_free_ char *filename = NULL;
                _cleanup_close_ int parent_fd = chase_and_open_parent_at(
                                root_fd, root_fd, m->where, CHASE_MKDIR_0755, &filename);
                if (parent_fd < 0) {
                        log_debug_errno(parent_fd, "Failed to pre-create parent of '%s' while the root is still "
                                        "writable, ignoring: %m", m->where);
                        continue;
                }

                _cleanup_close_ int subdir_fd = -EBADF;
                r = chaseat(root_fd, parent_fd, filename,
                            CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                            /* ret_path= */ NULL, &subdir_fd);
                if (r < 0)
                        log_debug_errno(r, "Failed to pre-create mount point '%s' while the root is still "
                                        "writable, ignoring: %m", m->where);
        }

        if (!FLAGS_SET(flags, MSTACK_DEFER_MOUNT)) {
                r = mstack_apply_bind_mounts(mstack, root_fd, where, flags, /* volatile_only= */ false);
                if (r < 0)
                        return r;
        }

        /* root/ now always folds into the overlay as its base layer whenever one exists (see
         * mstack_make_overlayfs()/mount_is_ro()), so a plain root/ entry no longer needs special
         * protection here - 'writable' alone (does an rw/ or synthetic --volatile=overlay layer exist?)
         * is correct. A throwaway tmpfs root (has_tmpfs_root, no real root/ entry backing it - e.g. from
         * --volatile=yes) has nothing to protect and is never tied to an rw/ layer's writability at all,
         * so it stays writable unless the caller explicitly asked for read-only. A plain root/-only stack
         * (no layer@, no rw/, root_mount still set) deliberately defaults to read-only here too, same as
         * ever - it has no writable layer of its own either, and read-only-by-default is the safe choice
         * absent an explicit --volatile= or rw/ opt-in (see TEST-13-NSPAWN.mstack.sh's "tmpfs@ present on
         * a read-only rootfs" coverage, which relies on exactly this). */
        bool root_writable = mstack->root_mount ? writable : !FLAGS_SET(flags, MSTACK_RDONLY);

        /* Recursing on root is only safe once nothing else is already attached under it: bind@/robind@
         * mounts (attached above when not MSTACK_DEFER_MOUNT) and the /usr/ extracted by --volatile=yes
         * (attached above unconditionally, regardless of MSTACK_DEFER_MOUNT) would otherwise have their
         * own, independently-decided attributes incorrectly overwritten. */
        bool root_recursive_ok = FLAGS_SET(flags, MSTACK_DEFER_MOUNT) && !attached_usr;
        r = mstack_apply_attr(root_fd, MSTACK_ROOT, root_writable, flags, root_recursive_ok);
        if (r < 0)
                return r;

        /* Entries synthesized from --volatile= go up here, as part of assembly, whether or not the caller
         * defers its own. They only ever target paths the root itself owns (/var), never one of the API VFS
         * paths a caller mounts over afterwards, so there is nothing for them to be shadowed by - and
         * attaching them now is what lets the whole root be idmapped as one piece, instead of needing a
         * second post-idmap phase to re-attach submounts a non-recursive remount would have orphaned.
         *
         * This deliberately comes *after* the root attribute pass above: a --volatile=state /var must stay
         * writable on top of a read-only root, and the recursive variant of that pass would otherwise
         * overwrite its attributes. Each entry sets its own attributes and propagation as it is attached. */
        r = mstack_apply_bind_mounts(mstack, root_fd, where, flags, /* volatile_only= */ true);
        if (r < 0)
                return r;

        /* If we have a tmpfs root, the above might have created mount point inodes. Hence we left the tmpfs
         * writable for that. Let's fix that now. Also, let's enable propagation for the future. (Reminder:
         * we disconnect propagation from the host, but we *want* propagation by default for everything
         * created further down the tree. Hence we'll set MS_SHARED here right-away.) */
        r = mstack_apply_propagation(root_fd);
        if (r < 0)
                return r;

        if (ret_root_fd)
                *ret_root_fd = TAKE_FD(root_fd);

        return 0;
}

int mstack_apply(
                const char *dir,
                int dir_fd,
                const char *where,
                const char *temp_mount_dir,
                sd_varlink *link,
                int userns_fd,
                const ImagePolicy *image_policy,
                const ImageFilter *image_filter,
                MStackFlags flags,
                uid_t uid_shift,
                int *ret_root_fd) {
        int r;

        assert(where);

        /* MSTACK_DEFER_MOUNT asks for the caller's bind@/robind@/tmpfs@ entries to be attached in a
         * second pass, which the caller runs itself via mstack_apply_bind_mounts_late(). This function
         * owns its MStack on the stack and frees it on return, so there would be nothing left to run
         * that pass against and the entries would simply be dropped. Refuse rather than lose them. */
        if (FLAGS_SET(flags, MSTACK_DEFER_MOUNT))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "MSTACK_DEFER_MOUNT needs a caller-owned MStack to run the deferred "
                                       "pass against; use the individual steps instead of mstack_apply().");

        _cleanup_(mstack_done) MStack mstack = MSTACK_INIT;
        r = mstack_load_now(&mstack, dir, dir_fd, flags);
        if (r < 0)
                return r;

        r = mstack_open_images(&mstack, link, userns_fd, image_policy, image_filter, flags);
        if (r < 0)
                return r;

        _cleanup_(rmdir_and_freep) char *t = NULL;
        if (!temp_mount_dir) {
                r = mkdtemp_malloc("/tmp/mstack-temporary-XXXXXX", &t);
                if (r < 0)
                        return r;

                temp_mount_dir = t;
        }

        r = mstack_make_mounts(&mstack, temp_mount_dir, flags, uid_shift);
        if (r < 0)
                return r;

        return mstack_bind_mounts(&mstack, where, /* where_fd= */ -EBADF, flags, ret_root_fd);
}

int mstack_load(const char *dir, int dir_fd, MStack **ret) {
        int r;

        assert(ret);

        /* Well-known errors:
         *
         *     -ENOTUNIQ → Multiple conflicting layers for the same path defined
         *     -EBADMSG  → Bad file suffix, inode type for layer, or unrecognized entry
         */

        _cleanup_(mstack_freep) MStack *mstack = new(MStack, 1);
        if (!mstack)
                return -ENOMEM;

        *mstack = MSTACK_INIT;

        r = mstack_load_now(mstack, dir, dir_fd, /* flags= */ 0);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(mstack);
        return 0;
}

int mstack_is_read_only(MStack *mstack) {
        assert(mstack);

        /* Checks if the mstack consists of only read-only layers and bind mounts */

        if (mstack->has_tmpfs_root)
                return false;

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if (IN_SET(m->mount_type, MSTACK_ROOT, MSTACK_RW, MSTACK_BIND, MSTACK_TMPFS))
                        return false;

        return true;
}

int mstack_is_foreign_uid_owned(MStack *mstack) {
        int r;

        assert(mstack);

        /* Checks if any of the layers are owned by the host's foreign UID range */

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {

                if (!IN_SET(m->image_type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME))
                        continue;

                assert(m->what_fd >= 0);

                struct stat st;
                if (fstat(m->what_fd, &st) < 0)
                        return -errno;

                r = stat_verify_directory(&st);
                if (r < 0)
                        return r;

                if (uid_is_foreign(st.st_uid))
                        return true;
        }

        return false;
}

static const char *const mstack_mount_type_table[] = {
        [MSTACK_ROOT]   = "root",
        [MSTACK_LAYER]  = "layer",
        [MSTACK_RW]     = "rw",
        [MSTACK_TMPFS]  = "tmpfs",
        [MSTACK_BIND]   = "bind",
        [MSTACK_ROBIND] = "robind",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(mstack_mount_type, MStackMountType);
