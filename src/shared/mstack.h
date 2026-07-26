/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "discover-image.h"
#include "forward.h"
#include "mount-util.h"
#include "volatile-util.h"

typedef enum MStackFlags {
        MSTACK_MKDIR        = 1 << 0, /* when mounting, create top-level inode to mount on top */
        MSTACK_RDONLY       = 1 << 1,
        MSTACK_DEFER_MOUNT  = 1 << 2,
        MSTACK_BINDS_RDONLY = 1 << 3, /* Ensure bind@ mounts are read-only only if explicitly requested */
} MStackFlags;

/* Fixed idmap range applied together with a uid_shift, matching the single-userns-per-container
 * allocation size used throughout the rest of the mstack/nspawn userns machinery. */
#define MSTACK_UID_SHIFT_RANGE UINT32_C(65536)

typedef enum MStackMountType {
        MSTACK_ROOT,     /* optional "root" entry used as the base (bottommost) layer of the overlayfs
                          * stack when layer@/rw are also present, or as the root directly on its own */
        MSTACK_LAYER,    /* "layer@…" entries that are the lower (read-only) layers of an overlayfs stack */
        MSTACK_RW,       /* "rw" entry that is the upper (writable) layer of an overlayfs stack (contains two subdirs: 'data' + 'work') */
        MSTACK_TMPFS,    /* "tmpfs@…" entries that mount a fresh (writable) tmpfs on top at the indicated location */
        MSTACK_BIND,     /* "bind@…" entries that are (writable) bind mounted on top of the overlayfs */
        MSTACK_ROBIND,   /* "robind@…" similar, but read-only */
        _MSTACK_MOUNT_TYPE_MAX,
        _MSTACK_MOUNT_TYPE_INVALID = -EINVAL,
} MStackMountType;

typedef struct MStackMount {
        MStackMountType mount_type;
        char *what;
        int what_fd;
        int mount_fd;
        char *sort_key;
        char *where;
        ImageType image_type;
        DissectedImage *dissected_image;
        bool from_volatile;      /* Synthesized by mstack_merge_volatile() rather than configured by the
                                  * user. Such entries are attached during assembly (immediately after the
                                  * root, in mstack_bind_mounts()) instead of in the deferred pass: they
                                  * only ever target paths the root itself owns (/var), never one of the
                                  * API VFS paths a caller may still mount over afterwards, and attaching
                                  * them up front is what lets the root be idmapped as one piece. */
} MStackMount;

typedef struct MStack {
        char *path;
        MStackMount *mounts;
        size_t n_mounts;
        bool has_tmpfs_root;      /* If true, we need a throw-away tmpfs as root */
        bool has_overlayfs;       /* Indicates whether we need overlayfs (i.e. if there are more than a single layer */
        MStackMount *root_mount;  /* If there's a MOUNT_BIND/MOUNT_ROBIND/MOUNT_ROOT mount, this points to it */
        int root_mount_fd;
        uid_t tmpfs_uid_shift;    /* If not UID_INVALID, the uid=/gid= to apply to freshly created tmpfs mounts */
        RemountIdmapping idmapping; /* The mapping to use for the idmaps applied during assembly. Callers
                                     * that idmap the assembled root themselves can leave this at the
                                     * REMOUNT_IDMAPPING_NONE default. */
        uid_t uid_range;          /* The range that goes with it; MSTACK_UID_SHIFT_RANGE if unset */
        char *tmpfs_selinux_context; /* If set, the SELinux 'context=' to apply to freshly created tmpfs mounts */
        bool extract_usr_only;    /* --volatile=yes: after the normal assembly below, clone /usr/ out of
                                    * root_mount_fd into usr_extract_fd, then replace root_mount_fd with a
                                    * throwaway tmpfs (see mstack_make_mounts()) */
        int usr_extract_fd;       /* The /usr/ clone above, attached early (before the caller's own
                                    * idmap remount step) by mstack_bind_mounts() */
} MStack;

#define MSTACK_INIT                             \
        (MStack) {                                        \
                .root_mount_fd = -EBADF,                  \
                .tmpfs_uid_shift = UID_INVALID,           \
                .idmapping = REMOUNT_IDMAPPING_NONE,      \
                .uid_range = MSTACK_UID_SHIFT_RANGE,      \
                .usr_extract_fd = -EBADF,                 \
        }

MStack* mstack_free(MStack *mstack);
DEFINE_TRIVIAL_CLEANUP_FUNC(MStack*, mstack_free);

int mstack_load(const char *dir, int dir_fd, MStack **ret);

/* Wrap an already-mounted root directory (a detached mount fd, e.g. from open_tree(…, OPEN_TREE_CLONE))
 * as a fresh MStack with a single MSTACK_ROOT entry. Takes ownership of root_fd on success. Used for the
 * plain --directory=/--image= + --volatile= case, where the root has already been prepared and mounted. */
int mstack_new_from_root_fd(int root_fd, MStack **ret);

/* Merge the layers implied by a --volatile= mode into an existing MStack (either one loaded from a
 * .mstack/ directory, or one returned by mstack_new_from_root_fd()). Mutates 'mstack' in place and
 * re-normalizes it. The tmpfs_uid_shift/tmpfs_selinux_context arguments provide uid=/gid= and SELinux
 * 'context=' parity for any tmpfs created while realizing the merged layers (pass UID_INVALID / NULL to
 * skip). The entries this synthesizes are marked from_volatile and attached during assembly; a caller's
 * own bind@/robind@/tmpfs@ entries are still attached later by mstack_apply_bind_mounts(), as usual. */
int mstack_merge_volatile(MStack *mstack, VolatileMode mode, uid_t tmpfs_uid_shift, const char *tmpfs_selinux_context);

int mstack_open_images(MStack *mstack, sd_varlink *mountfsd_link, int userns_fd, const ImagePolicy *image_policy, const ImageFilter *image_filter, MStackFlags flags);
bool mstack_has_writable_layers(MStack *mstack, MStackFlags flags);
int mstack_make_mounts(MStack *mstack, const char *temp_mount_dir, MStackFlags flags, uid_t uid_shift);
/* Attaches one phase's worth of bind@/robind@/tmpfs@ entries. With 'volatile_only' the entries
 * mstack_merge_volatile() synthesized are attached (during assembly, while the root is still being put
 * together); without it the caller's own entries are, which is what the deferred post-API-VFS pass does.
 * The two sets are disjoint, so neither phase ever attaches anything twice. */
int mstack_apply_bind_mounts(MStack *mstack, int root_fd, const char *where, MStackFlags flags, bool volatile_only);
int mstack_bind_mounts(MStack *mstack, const char *where, int where_fd, MStackFlags flags, int *ret_root_fd);

/* The four calls above in one. uid_shift may be UID_INVALID to skip idmapping (fixed range
 * MSTACK_UID_SHIFT_RANGE otherwise). */
int mstack_apply(
                const char *dir,
                int dir_fd,
                const char *where,
                const char *temp_mount_dir,
                sd_varlink *mountfsd_link,
                int userns_fd,
                const ImagePolicy *image_policy,
                const ImageFilter *image_filter,
                MStackFlags flags,
                uid_t uid_shift,
                int *ret_root_fd);

int mstack_is_read_only(MStack *mstack);
int mstack_is_foreign_uid_owned(MStack *mstack);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(mstack_mount_type, MStackMountType);
