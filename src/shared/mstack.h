/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "discover-image.h"
#include "shared-forward.h"

typedef enum MStackFlags {
        MSTACK_MKDIR  = 1 << 0, /* when mounting, create top-level inode to mount on top */
        MSTACK_RDONLY = 1 << 1,
} MStackFlags;

typedef enum MStackMountType {
        MSTACK_ROOT,     /* optional "root" entry used as root, with the layer@/rw layers only used for /usr/ */
        MSTACK_LAYER,    /* "layer@…" entries that are the lower (read-only) layers of an overlayfs stack */
        MSTACK_RW,       /* "rw" entry that is the upper (writable) layer of an overlayfs stack (contains two subdirs: 'data' + 'work') */
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
} MStackMount;

typedef struct MStack {
        char *path;
        MStackMount *mounts;
        size_t n_mounts;
        bool has_tmpfs_root;      /* If true, we need a throw-away tmpfs as root */
        bool has_overlayfs;       /* Indicates whether we need overlayfs (i.e. if there are more than a single layer */
        MStackMount *root_mount;  /* If there's a MOUNT_BIND/MOUNT_ROBIND/MOUNT_ROOT mount, this points to it */
        int root_mount_fd;
        int usr_mount_fd;
} MStack;

#define MSTACK_INIT                             \
        (MStack) {                              \
                .root_mount_fd = -EBADF,        \
                .usr_mount_fd = -EBADF,         \
        }

MStack *mstack_free(MStack *mstack);
DEFINE_TRIVIAL_CLEANUP_FUNC(MStack*, mstack_free);

int mstack_load(const char *dir, int dir_fd, MStack **ret);
int mstack_open_images(MStack *mstack, int userns_fd, const ImagePolicy *image_policy, const ImageFilter *image_filter, MStackFlags flags);
int mstack_make_mounts(MStack *mstack, const char *temp_mount_dir, MStackFlags flags);
int mstack_bind_mounts(MStack *mstack, const char *where, int where_fd, MStackFlags flags, int *ret_root_fd);

/* The four calls above in one */
int mstack_apply(const char *dir, int dir_fd, const char *where, const char *temp_mount_dir, int userns_fd, const ImagePolicy *image_policy, const ImageFilter *image_filter, MStackFlags flags, int *ret_root_fd);

int mstack_is_read_only(MStack *mstack);
int mstack_is_foreign_uid_owned(MStack *mstack);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(mstack_mount_type, MStackMountType);
