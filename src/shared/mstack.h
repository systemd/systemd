/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "discover-image.h"
#include "forward.h"
#include "mount-util.h"

typedef enum MStackFlags {
        MSTACK_MKDIR        = 1 << 0, /* when mounting, create top-level inode to mount on top */
        MSTACK_RDONLY       = 1 << 1,
        MSTACK_DEFER_MOUNT  = 1 << 2,
        MSTACK_BINDS_RDONLY = 1 << 3, /* Make bind@ mounts read-only even where the root itself stays
                                       * writable; implied by MSTACK_RDONLY, which covers the whole tree */
} MStackFlags;

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
        bool fd_consumed;        /* mount_fd was handed to move_mount() and then dropped: the mount lives
                                  * on, reachable by path, but we no longer hold a handle to it. Tracked so
                                  * mount_get_fd() can refuse rather than silently falling back to what_fd,
                                  * which refers to the source inode and not the mount at all. */
        bool synthetic;          /* Conjured by mstack rather than found on disk: the rw/ layer
                                  * --volatile=overlay adds has no backing until mstack_make_mounts()
                                  * realizes a throwaway tmpfs for it. Recorded rather than inferred from
                                  * the fds being unset, because that inference stops being true the
                                  * moment the backing is created - so anything asking after that point
                                  * would get a different answer to the same question. */
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
        uid_t uid_range;          /* The range that goes with it; USERNS_RANGE_SIZE if unset */
        char *tmpfs_selinux_context; /* If set, the SELinux 'context=' to apply to freshly created tmpfs mounts */
        bool extract_usr_only;    /* --volatile=yes: after the normal assembly below, clone /usr/ out of
                                    * root_mount_fd into usr_extract_fd, then replace root_mount_fd with a
                                    * throwaway tmpfs (see mstack_make_mounts()) */
        int usr_extract_fd;       /* The /usr/ clone above. mstack_bind_mounts() attaches it early (before
                                   * the caller's own idmap remount step, if it still has one) and drops
                                   * the fd again right after, since holding it would pin the mount and
                                   * make a later non-lazy umount of that path fail with EBUSY. */
} MStack;

#define MSTACK_INIT                             \
        (MStack) {                                        \
                .root_mount_fd = -EBADF,                  \
                .tmpfs_uid_shift = UID_INVALID,           \
                .idmapping = REMOUNT_IDMAPPING_NONE,      \
                .uid_range = USERNS_RANGE_SIZE,           \
                .usr_extract_fd = -EBADF,                 \
        }

/* The six entry types fall into two groups, and nearly every walk over a stack wants one group or the
 * other: root/, layer@ and rw/ are merged into the overlayfs, while bind@, robind@ and tmpfs@ are
 * attached on top of the assembled root afterwards. */
static inline bool mstack_mount_type_is_layer(MStackMountType t) {
        return IN_SET(t, MSTACK_ROOT, MSTACK_LAYER, MSTACK_RW);
}

static inline bool mstack_mount_type_is_overmount(MStackMountType t) {
        return IN_SET(t, MSTACK_BIND, MSTACK_ROBIND, MSTACK_TMPFS);
}

#define FOREACH_MSTACK_MOUNT(m, mstack)                                 \
        FOREACH_ARRAY(m, (mstack)->mounts, (mstack)->n_mounts)

#define FOREACH_MSTACK_MOUNT_TYPE(m, mstack, t)                         \
        FOREACH_MSTACK_MOUNT(m, mstack)                                 \
                if (m->mount_type != (t))                               \
                        continue;                                       \
                else

#define FOREACH_MSTACK_LAYER(m, mstack)                                 \
        FOREACH_MSTACK_MOUNT(m, mstack)                                 \
                if (!mstack_mount_type_is_layer(m->mount_type))         \
                        continue;                                       \
                else

#define FOREACH_MSTACK_OVERMOUNT(m, mstack)                             \
        FOREACH_MSTACK_MOUNT(m, mstack)                                 \
                if (!mstack_mount_type_is_overmount(m->mount_type))     \
                        continue;                                       \
                else

/* The layers in the order overlayfs wants them handed over: upper first, then each lower from the top
 * down. The array is sorted the other way round (by mount type, so root/ then layer@* then rw/), so
 * this walks it backwards - once here, rather than at every call site. */
#define FOREACH_MSTACK_LAYER_TOP_DOWN(m, mstack)                        \
        for (MStackMount *m = (mstack)->mounts + (mstack)->n_mounts;    \
             m-- > (mstack)->mounts; )                                  \
                if (!mstack_mount_type_is_layer(m->mount_type))         \
                        continue;                                       \
                else

typedef enum MStackLayerIdentity {
        MSTACK_LAYER_IDENTITY_NONE,  /* leave the layer's ownership exactly as it is on disk */
        MSTACK_LAYER_IDENTITY_IDMAP, /* present the on-disk owner 0 as the container's root */
        MSTACK_LAYER_IDENTITY_CHOWN, /* hand the layer's own inodes to the container's root outright */
        _MSTACK_LAYER_IDENTITY_MAX,
        _MSTACK_LAYER_IDENTITY_INVALID = -EINVAL,
} MStackLayerIdentity;

typedef enum MStackRootShape {
        MSTACK_ROOT_SHAPE_OVERLAY, /* several layers, merged */
        MSTACK_ROOT_SHAPE_BIND,    /* a lone root/ entry, bound directly */
        MSTACK_ROOT_SHAPE_TMPFS,   /* nothing persistent underneath, a throwaway tmpfs */
        _MSTACK_ROOT_SHAPE_MAX,
        _MSTACK_ROOT_SHAPE_INVALID = -EINVAL,
} MStackRootShape;

typedef enum MStackLayerRole {
        MSTACK_LAYER_ROLE_LOWER,          /* another read-only layer */
        MSTACK_LAYER_ROLE_UPPER,          /* the single writable one, as a data/work pair */
        MSTACK_LAYER_ROLE_UPPER_UNBACKED, /* the same, but with nothing on disk behind it yet: the rw/
                                           * layer --volatile=overlay conjures needs a throwaway tmpfs
                                           * to hold data/work before anything can be assembled */
        _MSTACK_LAYER_ROLE_MAX,
        _MSTACK_LAYER_ROLE_INVALID = -EINVAL,
} MStackLayerRole;

static inline bool mstack_layer_role_is_upper(MStackLayerRole r) {
        return IN_SET(r, MSTACK_LAYER_ROLE_UPPER, MSTACK_LAYER_ROLE_UPPER_UNBACKED);
}

typedef struct MStackLayerPlan {
        MStackMount *mount;
        MStackLayerRole role;
        MStackLayerIdentity identity;
        uid_t identity_uid;
} MStackLayerPlan;

/* Every decision, made before anything is mounted. Records derivations only: straight yes/no questions
 * about the kernel are asked of mstack_caps() at the point they are acted on, because copying one in here
 * would just create a second thing that can drift from the first, and observations that need I/O (does
 * this layer's data/ exist?) are left to whoever is standing in front of the filesystem. */
typedef struct MStackPlan {
        MStackRootShape shape;
        bool idmap_root_directly;
        uid_t root_uid_shift;
        bool extract_usr;
        MStackLayerPlan *layers;
        size_t n_layers;
} MStackPlan;

#define FOREACH_MSTACK_PLAN_LAYER(l, plan)                              \
        FOREACH_ARRAY(l, (plan)->layers, (plan)->n_layers)

MStackPlan* mstack_plan_free(MStackPlan *plan);
DEFINE_TRIVIAL_CLEANUP_FUNC(MStackPlan*, mstack_plan_free);

/* Works out the whole assembly strategy without touching anything, which is what makes it testable
 * without privileges. mstack_make_mounts() calls this itself; callers only need it directly to inspect
 * what would happen. */
int mstack_plan(MStack *mstack, MStackFlags flags, uid_t uid_shift, MStackPlan **ret);

MStack* mstack_free(MStack *mstack);
DEFINE_TRIVIAL_CLEANUP_FUNC(MStack*, mstack_free);

int mstack_load(const char *dir, int dir_fd, MStack **ret);

/* Wrap an already-mounted root directory (a detached mount fd, e.g. from open_tree(..., OPEN_TREE_CLONE))
 * as a fresh MStack with a single MSTACK_ROOT entry. Takes ownership of root_fd on success. Used for the
 * plain --directory=/--image= + --volatile= case, where the root has already been prepared and mounted. */
int mstack_new_from_root_fd(int root_fd, MStack **ret);

/* Merge the layers implied by a --volatile= mode into an existing MStack (either one loaded from a
 * .mstack/ directory, or one returned by mstack_new_from_root_fd()). Mutates 'mstack' in place and
 * re-normalizes it. The tmpfs_uid_shift/tmpfs_selinux_context arguments provide uid=/gid= and SELinux
 * 'context=' parity for any tmpfs created while realizing the merged layers (pass UID_INVALID / NULL to
 * skip). The entries this synthesizes are marked from_volatile and attached during assembly; a caller's
 * own bind@/robind@/tmpfs@ entries are still attached later by mstack_apply_bind_mounts_late(), as
 * usual. */
int mstack_merge_volatile(MStack *mstack, VolatileMode mode, uid_t tmpfs_uid_shift, const char *tmpfs_selinux_context);

int mstack_open_images(MStack *mstack, sd_varlink *mountfsd_link, int userns_fd, const ImagePolicy *image_policy, const ImageFilter *image_filter, MStackFlags flags);
bool mstack_has_writable_layers(MStack *mstack, MStackFlags flags);
int mstack_make_mounts(MStack *mstack, const char *temp_mount_dir, MStackFlags flags, uid_t uid_shift);
int mstack_bind_mounts(MStack *mstack, const char *where, int where_fd, MStackFlags flags, int *ret_root_fd);

/* The deferred half of the above: attaches the caller's own bind@/robind@/tmpfs@ entries, to be called
 * once the caller has finished mounting its own API VFS over the staged root. */
int mstack_apply_bind_mounts_late(MStack *mstack, const char *where, MStackFlags flags);

/* The four calls above in one. uid_shift may be UID_INVALID to skip idmapping (fixed range
 * USERNS_RANGE_SIZE otherwise). */
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
