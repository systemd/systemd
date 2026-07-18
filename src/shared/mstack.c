/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "chase.h"
#include "dissect-image.h"
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
#include "user-util.h"
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
                        /* A synthetic rw layer (e.g. from --volatile=overlay) carries no backing fd yet -
                         * it's only realized into a throwaway tmpfs later, in mstack_make_mounts(). Track
                         * it separately: it can't be collapsed into a MSTACK_BIND below like a real rw/
                         * entry could, since there's nothing to bind-mount yet. */
                        has_synthetic_rw = m->what_fd < 0 && m->mount_fd < 0;
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

        return m->what_fd;
}

int mstack_new_from_root_fd(int root_fd, MStack **ret) {
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
                .mount_fd = root_fd,
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

        if (mode == VOLATILE_NO)
                return 0;

        /* Remember the tmpfs parity settings; they are consulted whenever we realize a tmpfs below. */
        mstack->tmpfs_uid_shift = tmpfs_uid_shift;
        r = free_and_strdup_warn(&mstack->tmpfs_selinux_context, tmpfs_selinux_context);
        if (r < 0)
                return r;

        switch (mode) {

        case VOLATILE_OVERLAY:
                /* Demote any plain root into a read-only lower layer so the overlay covers the whole tree
                 * (not just /usr/), then add a synthetic writable upper layer on a throwaway tmpfs. */
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                        if (m->mount_type == MSTACK_ROOT)
                                m->mount_type = MSTACK_LAYER;

                if (mstack_find(mstack, MSTACK_RW, /* sort_key= */ NULL, /* where= */ NULL))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Cannot add volatile overlay: mount stack already has a writable layer.");

                if (!GREEDY_REALLOC(mstack->mounts, mstack->n_mounts + 1))
                        return -ENOMEM;

                mstack->mounts[mstack->n_mounts++] = (MStackMount) {
                        .mount_type = MSTACK_RW,
                        .what_fd = -EBADF, /* synthetic: tmpfs backing is realized in mstack_make_mounts() */
                        .mount_fd = -EBADF,
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

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if (m->mount_type == MSTACK_RW)
                        return true;

        return false;
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

        r = RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_FD, key, /* value= */ NULL, layer_fd));
        if (r != -EBADF && r != -EINVAL && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return r;

        /* overlayfs learnt support for FSCONFIG_SET_FD only with linux 6.13. On kernels 6.5–6.12,
         * the overlayfs parameter parser recognises the key but rejects the fd type with EINVAL.
         * Fall back to the /proc/self/fd/ string path for all of these. */

        // FIXME: This compatibility code path shall be removed once kernel 6.13
        //        becomes the new minimal baseline

        const char *layer_path = FORMAT_PROC_FD_PATH(layer_fd);
        log_debug_errno(r, "FSCONFIG_SET_FD for layer '%s' failed, falling back to FSCONFIG_SET with '%s': %m", key, layer_path);
        return RET_NERRNO(fsconfig(sb_fd, FSCONFIG_SET_STRING, key, layer_path, /* aux= */ 0));
}

static int mstack_make_tmpfs(MStack *mstack, const char *limits, int *ret_mnt_fd) {
        _cleanup_free_ char *options = NULL;
        int r;

        assert(mstack);
        assert(ret_mnt_fd);

        /* Creates a fresh tmpfs mount fd. On top of the base 'mode=0755' and the passed size/inode
         * limits we also apply uid=/gid= and the SELinux 'context=' (when plumbed in), for parity with
         * nspawn's volatile tmpfs handling. */
        const char *base = strjoina("mode=0755", strempty(limits));
        r = tmpfs_patch_options(base, mstack->tmpfs_uid_shift, mstack->tmpfs_selinux_context, &options);
        if (r < 0)
                return log_oom_debug();

        int mnt_fd = make_fsmount(
                        LOG_DEBUG,
                        empty_to_root(mstack->path),
                        "tmpfs",
                        MS_STRICTATIME,
                        options ?: base,
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
         * refuse the superblock to be created. */
        return RET_NERRNO(fsconfig(sb_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0));
}

static int mstack_make_overlayfs(
                MStack *mstack,
                const char *temp_mount_dir,
                MStackFlags flags,
                uid_t uid_shift,
                int *ret_overlayfs_mnt_fd) {

        int r;

        assert(mstack);
        assert(temp_mount_dir);
        assert(ret_overlayfs_mnt_fd);

        if (!mstack->has_overlayfs) {
                *ret_overlayfs_mnt_fd = -EBADF;
                return 0;
        }

        bool writable = mstack_has_writable_layers(mstack, flags);

        /* overlayfs cannot itself be the target of an idmapped mount (mount_setattr(MOUNT_ATTR_IDMAP) on an
         * already-merged overlay returns EINVAL) - the kernel only supports idmapping the individual layers
         * that go INTO an overlay, before they're merged. So if an idmap was requested, acquire the userns
         * once here and apply it to each layer's cloned mount fd below, before it's merged; the assembled
         * overlay then inherits the mapping from its already-idmapped layers. */
        _cleanup_close_ int uidmap_userns_fd = -EBADF;
        if (uid_is_valid(uid_shift)) {
                uidmap_userns_fd = make_userns(uid_shift, MSTACK_UID_SHIFT_RANGE, UID_INVALID, UID_INVALID, REMOUNT_IDMAPPING_NONE);
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

        /* If we operate unpriv, we have to attach the layers to a place in the fs, before we can pass them
         * to overlayfs (see comments below), hence fork off a child with a private mount namespace, so that
         * no one else sees that. */
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

                /* Every fd contributing a "lowerdir+" layer, plus the upperdir/workdir fds if any,
                 * kept open (rather than closed at the end of their loop iteration) so that, if the
                 * primary "lowerdir+" attempt below fails with EINVAL, we can still refer to them via
                 * FORMAT_PROC_FD_PATH() to build the legacy joined "lowerdir=" fallback. */
                _cleanup_free_ int *lower_fds = NULL;
                size_t n_lower_fds = 0;
                int upperdir_fd = -EBADF, workdir_fd = -EBADF;

                /* Kernel expects the stack in reverse order, hence go from back to front */
                for (size_t i = mstack->n_mounts; i > 0; i--) {
                        MStackMount *m = mstack->mounts + i - 1;

                        if (!IN_SET(m->mount_type, MSTACK_RW, MSTACK_LAYER, MSTACK_ROOT))
                                continue;

                        int source_fd = ASSERT_FD(mount_get_fd(m));
                        bool rw_readonly = m->mount_type == MSTACK_RW && mount_is_ro(mstack, m, flags);
                        bool rw_writable = m->mount_type == MSTACK_RW && !rw_readonly;
                        bool have_data_dir = true;

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
                                        report_errno_and_exit(errno_pipe_fds[1], -errno);
                                if (mkdirat(source_fd, "work", 0755) < 0 && errno != EEXIST)
                                        report_errno_and_exit(errno_pipe_fds[1], -errno);
                        } else if (rw_readonly) {
                                r = RET_NERRNO(faccessat(source_fd, "data", F_OK, 0));
                                if (r == -ENOENT) /* If the 'data' dir doesn't exist, just skip over this
                                                    * layer entirely, it apparently was never created, but
                                                    * that's fine for a read-only invocation */
                                        have_data_dir = false;
                                else if (r < 0)
                                        report_errno_and_exit(errno_pipe_fds[1], r);
                        }

                        /* overlayfs refuses to work with layers on mounts not owned by our userns, hence create a
                         * clone that is owned by our userns */
                        _cleanup_close_ int cloned_fd = mount_fd_clone(source_fd, /* recursive= */ false, /* replacement_fd= */ NULL);
                        if (cloned_fd < 0)
                                report_errno_and_exit(errno_pipe_fds[1], cloned_fd);

                        /* Idmap the layer here, while it's still a fresh, unattached clone with nothing yet
                         * created through it: this is the only point at which the kernel allows
                         * MOUNT_ATTR_IDMAP for what will become part of an overlay (see the
                         * uidmap_userns_fd comment above). */
                        if (uidmap_userns_fd >= 0 &&
                            mount_setattr(cloned_fd, "", AT_EMPTY_PATH,
                                          &(struct mount_attr) {
                                                  .attr_set = MOUNT_ATTR_IDMAP,
                                                  .userns_fd = uidmap_userns_fd,
                                          }, sizeof(struct mount_attr)) < 0) {
                                log_debug_errno(errno, "Failed to idmap layer %s: %m", m->what);
                                report_errno_and_exit(errno_pipe_fds[1], -errno);
                        }

                        /* When working with detached mounts overlayfs (which requires kernel 6.14) currently
                         * insists on upperdir being the root inode of the mount. But that collides with the
                         * requirement that upperdir/workdir are on the same mount and siblings. Bummer. To
                         * work around this we'll temporarily attach the thing, which relaxes the rules
                         * sufficiently. */
                        if (move_mount(cloned_fd, "", -EBADF, temp_mount_dir, MOVE_MOUNT_F_EMPTY_PATH) < 0)
                                report_errno_and_exit(errno_pipe_fds[1], -errno);

                        /* Open the layer immediately after attaching */
                        _cleanup_close_ int temp_fd = open(temp_mount_dir, O_PATH|O_CLOEXEC);
                        if (temp_fd < 0)
                                report_errno_and_exit(errno_pipe_fds[1], -errno);

                        switch (m->mount_type) {

                        case MSTACK_RW: {
                                if (rw_readonly) {
                                        if (!have_data_dir)
                                                break;

                                        _cleanup_close_ int data_fd = openat(temp_fd, "data", O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY);
                                        if (data_fd < 0) {
                                                log_debug_errno(errno, "Failed to open 'data' directory below 'rw' layer: %m");
                                                report_errno_and_exit(errno_pipe_fds[1], -errno);
                                        }

                                        /* Downgrade to regular lowerdir if read-only is requested */
                                        r = fsconfig_add_layer(sb_fd, "lowerdir+", data_fd);
                                        if (r < 0) {
                                                log_debug_errno(r, "Failed to set mount layer lowerdir+=%s/data: %m", m->what);
                                                report_errno_and_exit(errno_pipe_fds[1], r);
                                        }

                                        if (!GREEDY_REALLOC(lower_fds, n_lower_fds + 1))
                                                report_errno_and_exit(errno_pipe_fds[1], -ENOMEM);
                                        lower_fds[n_lower_fds++] = TAKE_FD(data_fd);
                                } else {
                                        /* 'data'/'work' were already created (if missing) on the pre-clone
                                         * source above, so just open them here. */
                                        _cleanup_close_ int data_fd = openat(temp_fd, "data", O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY);
                                        if (data_fd < 0) {
                                                log_debug_errno(errno, "Failed to open 'data' directory below 'rw' layer: %m");
                                                report_errno_and_exit(errno_pipe_fds[1], -errno);
                                        }

                                        _cleanup_close_ int work_fd = openat(temp_fd, "work", O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY);
                                        if (work_fd < 0) {
                                                log_debug_errno(errno, "Failed to open 'work' directory below 'rw' layer: %m");
                                                report_errno_and_exit(errno_pipe_fds[1], -errno);
                                        }

                                        /* rm_rf_children() takes possession of the fd no matter what, let's dup it here */
                                        int dup_fd = fcntl(work_fd, F_DUPFD_CLOEXEC, 3);
                                        if (dup_fd < 0) {
                                                log_debug_errno(errno, "Failed to duplicate work fd: %m");
                                                report_errno_and_exit(errno_pipe_fds[1], -errno);
                                        }

                                        /* Empty the work directory, just in case it existed before. It's supposed to be empty. */
                                        r = rm_rf_children(dup_fd, REMOVE_PHYSICAL, /* root_dev= */ NULL);
                                        if (r < 0)
                                                log_debug_errno(r, "Failed to empty 'work' directory below 'rw' layer, ignoring: %m");

                                        r = fsconfig_add_layer(sb_fd, "upperdir", data_fd);
                                        if (r < 0) {
                                                log_debug_errno(r, "Failed to set mount layer upperdir=%s/data: %m", m->what);
                                                report_errno_and_exit(errno_pipe_fds[1], r);
                                        }

                                        r = fsconfig_add_layer(sb_fd, "workdir", work_fd);
                                        if (r < 0) {
                                                log_debug_errno(r, "Failed to set mount layer workdir=%s/work: %m", m->what);
                                                report_errno_and_exit(errno_pipe_fds[1], r);
                                        }

                                        upperdir_fd = TAKE_FD(data_fd);
                                        workdir_fd = TAKE_FD(work_fd);

                                        break;
                                }
                                break;
                        }

                        case MSTACK_LAYER:
                        case MSTACK_ROOT:
                                /* root/ sorts before every layer@ (MSTACK_ROOT is the lowest mount type),
                                 * so it's processed last in this reverse loop and naturally ends up as the
                                 * bottommost lowerdir here: the base that layer@/rw sit on top of, across
                                 * the whole tree rather than just /usr/. */
                                r = fsconfig_add_layer(sb_fd, "lowerdir+", temp_fd);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to set mount layer lowerdir+=%s: %m", m->what);
                                        report_errno_and_exit(errno_pipe_fds[1], r);
                                }

                                if (!GREEDY_REALLOC(lower_fds, n_lower_fds + 1))
                                        report_errno_and_exit(errno_pipe_fds[1], -ENOMEM);
                                lower_fds[n_lower_fds++] = TAKE_FD(temp_fd);

                                break;

                        default:
                                break;
                        }
                }

                r = mstack_overlayfs_create(sb_fd, writable, empty_to_root(mstack->path));
                if (r == -EINVAL && n_lower_fds > 0) {
                        log_debug_errno(r, "Failed to realize overlayfs via incremental 'lowerdir+', retrying with a single joined 'lowerdir=': %m");

                        _cleanup_strv_free_ char **lower_paths = NULL;
                        FOREACH_ARRAY(fd, lower_fds, n_lower_fds)
                                if (strv_extend(&lower_paths, FORMAT_PROC_FD_PATH(*fd)) < 0)
                                        report_errno_and_exit(errno_pipe_fds[1], -ENOMEM);

                        _cleanup_free_ char *joined = strv_join(lower_paths, ":");
                        if (!joined)
                                report_errno_and_exit(errno_pipe_fds[1], -ENOMEM);

                        if (fsconfig(sb_fd_fallback, FSCONFIG_SET_STRING, "lowerdir", joined, /* aux= */ 0) < 0)
                                report_errno_and_exit(errno_pipe_fds[1], -errno);

                        if (upperdir_fd >= 0 &&
                            fsconfig(sb_fd_fallback, FSCONFIG_SET_STRING, "upperdir", FORMAT_PROC_FD_PATH(upperdir_fd), /* aux= */ 0) < 0)
                                report_errno_and_exit(errno_pipe_fds[1], -errno);

                        if (workdir_fd >= 0 &&
                            fsconfig(sb_fd_fallback, FSCONFIG_SET_STRING, "workdir", FORMAT_PROC_FD_PATH(workdir_fd), /* aux= */ 0) < 0)
                                report_errno_and_exit(errno_pipe_fds[1], -errno);

                        r = mstack_overlayfs_create(sb_fd_fallback, writable, empty_to_root(mstack->path));
                }
                if (r < 0)
                        report_errno_and_exit(errno_pipe_fds[1], r);

                report_errno_and_exit(errno_pipe_fds[1], 0);
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

int mstack_make_mounts(
                MStack *mstack,
                const char *temp_mount_dir,
                MStackFlags flags,
                uid_t uid_shift) {

        int r;

        assert(mstack);
        assert(temp_mount_dir);

        /* Synthetic 'rw' layers (e.g. from --volatile=overlay) carry no on-disk backing; realize a
         * throwaway tmpfs to hold their 'data'/'work' subdirs before assembling the overlayfs. */
        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts)
                if (m->mount_type == MSTACK_RW && m->what_fd < 0 && m->mount_fd < 0) {
                        r = mstack_make_tmpfs(mstack, TMPFS_LIMITS_ROOTFS, &m->mount_fd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to create tmpfs backing for synthetic rw layer: %m");
                }

        _cleanup_close_ int overlayfs_mnt_fd = -EBADF;
        r = mstack_make_overlayfs(mstack, temp_mount_dir, flags, uid_shift, &overlayfs_mnt_fd);
        if (r < 0)
                return r;
        if (r > 0)
                log_debug("Acquired mstack overlayfs mount.");

        assert(mstack->root_mount_fd < 0);
        if (mstack->root_mount && !mstack->has_overlayfs) {
                /* If there's also an overlay (layer@/rw), root/ was already folded into it as the base
                 * lowerdir by mstack_make_overlayfs() above, so the overlay fd itself becomes our root
                 * below; there's nothing further to do for root/ here in that case. */
                assert(!mstack->has_tmpfs_root);

                mstack->root_mount_fd = fcntl(mount_get_fd(mstack->root_mount), F_DUPFD_CLOEXEC, 3);
                if (mstack->root_mount_fd < 0)
                        return log_debug_errno(errno, "Failed to create root bind mount: %m");

                log_debug("Acquired mstack root bind mount.");

        } else if (mstack->has_tmpfs_root) {
                r = mstack_make_tmpfs(mstack, TMPFS_LIMITS_ROOTFS, &mstack->root_mount_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create root tmpfs: %m");

                log_debug("Acquired root tmpfs mount.");
        }

        /* If we acquired no other root fs (or root/ was folded into the overlay above as its base layer),
         * then the overlayfs is our root */
        if (mstack->root_mount_fd < 0)
                mstack->root_mount_fd = TAKE_FD(overlayfs_mnt_fd);
        else if (uid_is_valid(uid_shift)) {
                /* Unlike the overlay case above (already idmapped layer-by-layer before merging), this is a
                 * plain, single, not-yet-attached mount (a bind of root/ alone, or a throwaway tmpfs) -
                 * regular filesystems ARE a valid target for MOUNT_ATTR_IDMAP directly. */
                _cleanup_close_ int userns_fd = make_userns(uid_shift, MSTACK_UID_SHIFT_RANGE, UID_INVALID, UID_INVALID, REMOUNT_IDMAPPING_NONE);
                if (userns_fd < 0)
                        return log_debug_errno(userns_fd, "Failed to create idmap userns: %m");

                if (mount_setattr(mstack->root_mount_fd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = MOUNT_ATTR_IDMAP,
                                          .userns_fd = userns_fd,
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_debug_errno(errno, "Failed to idmap root mount: %m");
        }

        if (mstack->extract_usr_only) {
                /* --volatile=yes only keeps /usr/ around; validate the tree has adopted the merged-/usr
                 * scheme before going any further, same as the pre-mstack implementation did: /bin (and by
                 * extension /sbin, /lib, /lib64) must either not exist yet (a naked /usr/, the rest is
                 * created below by base_filesystem_create()) or already be a symlink into /usr/. Anything
                 * else (in particular a real /bin/ directory) means /usr/ alone isn't enough to boot. */
                struct stat st;
                if (fstatat(mstack->root_mount_fd, "bin", &st, AT_SYMLINK_NOFOLLOW) < 0) {
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

                /* We now have a fully assembled tree at root_mount_fd (whatever combination of root/,
                 * layer@, rw/ that represents); clone /usr/ out of it - the same
                 * open_tree()-on-a-detached-mount pattern used for overlayfs_mnt_fd above works
                 * identically here regardless of which of the three paths above produced root_mount_fd -
                 * before replacing root_mount_fd itself with a throwaway tmpfs. */
                mstack->usr_extract_fd = open_tree(mstack->root_mount_fd, "usr",
                                                   OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW);
                if (mstack->usr_extract_fd < 0)
                        return log_debug_errno(errno, "Failed to clone /usr/ for --volatile=yes: %m");

                if (mount_setattr(mstack->usr_extract_fd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = MOUNT_ATTR_RDONLY,
                                          .propagation = MS_PRIVATE, /* disconnect us from bind mount source */
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

                log_debug("Extracted /usr/ for --volatile=yes, replaced root with a throwaway tmpfs.");
        }

        return 0;
}

/* Extracted to make it reusable for mstack deferred binds. */
static int mstack_apply_attr(int dfd, MStackMountType mount_type, bool writable, MStackFlags flags) {
        /* ROBIND is always read-only.
         * ROOT is read-only if writable is false (due to MSTACK_RDONLY or no write layers).
         * BIND is read-only if and only if MSTACK_BINDS_RDONLY (--read-only flag)
         * is explicitly set. */
        bool rdonly = mount_type == MSTACK_ROBIND ||
                      (mount_type == MSTACK_ROOT && !writable) ||
                      (mount_type == MSTACK_BIND && FLAGS_SET(flags, MSTACK_BINDS_RDONLY));

        /* Do not use AT_RECURSIVE on the ROOT mount to avoid recursively overwriting
         * attributes of bind mounts (like bind@) attached inside it earlier. */
        int attr_flags = AT_EMPTY_PATH | (mount_type == MSTACK_ROOT ? 0 : AT_RECURSIVE);

        if (mount_setattr(dfd, "", attr_flags,
                          &(struct mount_attr) {
                                  .attr_set = rdonly ? MOUNT_ATTR_RDONLY : 0,
                                  .attr_clr = rdonly ? 0 : MOUNT_ATTR_RDONLY,
                          }, sizeof(struct mount_attr)) < 0)
                return log_debug_errno(errno, "Failed to set mount attributes: %m");

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

/* Extracted to make it reusable for mstack deferred binds. */
int mstack_apply_bind_mounts(
                MStack *mstack,
                int root_fd,
                const char *where,
                MStackFlags flags) {
        int r;

        assert(mstack);
        assert(root_fd >= 0);
        assert(where);

        bool writable = mstack_has_writable_layers(mstack, flags);

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                if (!IN_SET(m->mount_type, MSTACK_BIND, MSTACK_ROBIND, MSTACK_TMPFS) ||
                    m == mstack->root_mount)
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

                _cleanup_close_ int parent_fd = -EBADF;
                _cleanup_close_ int subdir_fd = -EBADF;
                _cleanup_free_ char *filename = NULL;

                /* Resolve parent directory. This allows resolving benign path symlinks
                 *    (like /var/run -> /run) safely while staying within the root_fd boundary.
                 *    We do NOT pass CHASE_PROHIBIT_SYMLINKS here to allow resolution. */
                parent_fd = chase_and_open_parent_at(root_fd, root_fd, m->where, CHASE_MKDIR_0755, &filename);
                if (parent_fd == -EROFS)
                        return log_error_errno(parent_fd, "Failed to create parent directory for '%s': root is read-only. "
                                        "Add an rw/ directory to the .mstack/, use --volatile= to provide a writable root layer, "
                                        "or pre-create bind target directory in the base layer: %m", m->where);
                if (parent_fd < 0)
                        return log_debug_errno(parent_fd, "Failed to open parent of mount point '%s': %m", m->where);

                /* Resolve, validate, and/or create the leaf target directory relative to parent_fd. */
                r = chaseat(root_fd, parent_fd, filename, CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &subdir_fd);
                if (r == -EROFS)
                        return log_error_errno(r, "Failed to create mount point directory '%s': root is read-only. "
                                        "Add an rw/ directory to the .mstack/, use --volatile= to provide a writable root layer, "
                                        "or pre-create bind target directory in the base layer: %m", m->where);
                if (r < 0) {
                        if (IN_SET(r, -ELOOP, -EREMCHG))
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "Security violation: Mount target '%s' is a symbolic link.",
                                                       m->where);

                        return log_debug_errno(r, "Failed to open mount point inode '%s': %m", m->where);
                }

                if (move_mount(mount_fd, "", subdir_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                        return log_debug_errno(errno, "Failed to attach bind mount to '%s' subdir: %m", m->where);

                /* Set mount attributes on each bind mount fd after attaching it.
                 * For the non-deferred path (called from mstack_bind_mounts()), this is
                 * redundant since mstack_bind_mounts() applies a recursive mount_setattr()
                 * on root_fd afterward - but mount_setattr() is idempotent so it's harmless.
                 * For the deferred path (called from apply_deferred_mstack_bind_mounts()),
                 * this is the only place attributes are set on these mounts since the
                 * recursive root_fd call already happened before they were attached. */
                r = mstack_apply_attr(mount_fd, m->mount_type, writable, flags);
                if (r < 0)
                        return r;

                r = mstack_apply_propagation(mount_fd);
                if (r < 0)
                        return r;

                log_debug("Attached mstack '%s/' mount to '%s%s/'.", m->where, where, m->where);
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

        assert(mstack->root_mount_fd >= 0);
        if (move_mount(mstack->root_mount_fd, "", where_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH) < 0)
                return log_debug_errno(errno, "Failed to attach mstack root mount to '%s': %m", where);

        log_debug("Attached mstack root mount to '%s'.", where);

        _cleanup_close_ int root_fd = open(where, O_CLOEXEC|O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (root_fd < 0)
                return log_debug_errno(errno, "Failed to mount root mount '%s': %m", where);

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

                log_debug("Attached extracted /usr/ to '%s/usr/'.", where);
        }

        if (!FLAGS_SET(flags, MSTACK_DEFER_MOUNT)) {
                r = mstack_apply_bind_mounts(mstack, root_fd, where, flags);
                if (r < 0)
                        return r;
        } else {
                /* Pre-create bind mount target directories while root is still writable.
                 * The actual mounts are deferred to after mount_all(), at which point the
                 * root may already be read-only. Directories under paths that mount_all()
                 * replaces (e.g. /run, /tmp) will be hidden, but the deferred apply
                 * recreates them on the new writable mounts. */
                FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                        if (!IN_SET(m->mount_type, MSTACK_BIND, MSTACK_ROBIND, MSTACK_TMPFS) ||
                            m == mstack->root_mount)
                                continue;

                        _cleanup_free_ char *filename = NULL;
                        _cleanup_close_ int parent_fd = chase_and_open_parent_at(
                                        root_fd, root_fd, m->where, CHASE_MKDIR_0755, &filename);
                        if (parent_fd < 0)
                                continue;

                        _cleanup_close_ int subdir_fd = -EBADF;
                        (void) chaseat(root_fd, parent_fd, filename,
                                       CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                                       /* ret_path= */ NULL, &subdir_fd);
                }
        }

        /* root/ now always folds into the overlay as its base layer whenever one exists (see
         * mstack_make_overlayfs()/mount_is_ro()), so a plain root/ entry no longer needs special
         * protection here - 'writable' alone (does an rw/ or synthetic --volatile=overlay layer exist?)
         * is correct. A throwaway tmpfs root (has_tmpfs_root, no real root/ entry backing it - e.g. from
         * --volatile=yes) has nothing to protect and is never tied to an rw/ layer's writability at all,
         * so it stays writable unless the caller explicitly asked for read-only. */
        bool root_writable = mstack->root_mount ? writable : !FLAGS_SET(flags, MSTACK_RDONLY);
        r = mstack_apply_attr(root_fd, MSTACK_ROOT, root_writable, flags);
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
