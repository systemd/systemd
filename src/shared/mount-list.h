/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "dissect-image.h"
#include "os-util.h"

typedef enum MountMode {
        /* This is ordered by priority! */
        MOUNT_INACCESSIBLE,
        MOUNT_OVERLAY,
        MOUNT_IMAGE,
        MOUNT_BIND,
        MOUNT_BIND_RECURSIVE,
        MOUNT_PRIVATE_TMP,
        MOUNT_PRIVATE_DEV,
        MOUNT_BIND_DEV,
        MOUNT_EMPTY_DIR,
        MOUNT_PRIVATE_SYSFS,
        MOUNT_BIND_SYSFS,
        MOUNT_PROCFS,
        MOUNT_PRIVATE_CGROUP2FS,
        MOUNT_READ_ONLY,
        MOUNT_READ_WRITE,
        MOUNT_NOEXEC,
        MOUNT_EXEC,
        MOUNT_TMPFS,
        MOUNT_RUN,
        MOUNT_PRIVATE_TMPFS,       /* Mounted outside the root directory, and used by subsequent mounts */
        MOUNT_EXTENSION_DIRECTORY, /* Bind-mounted outside the root directory, and used by subsequent mounts */
        MOUNT_EXTENSION_IMAGE,     /* Mounted outside the root directory, and used by subsequent mounts */
        MOUNT_MQUEUEFS,
        MOUNT_READ_WRITE_IMPLICIT, /* Should have the lowest priority. */
        MOUNT_BPFFS,               /* Special mount for bpffs, which is mounted with fsmount() and move_mount() */
        _MOUNT_MODE_MAX,
        _MOUNT_MODE_INVALID = -EINVAL,
} MountMode;

typedef enum MountEntryState {
        MOUNT_PENDING,
        MOUNT_APPLIED,
        MOUNT_SKIPPED,
        _MOUNT_ENTRY_STATE_MAX,
        _MOUNT_ENTRY_STATE_INVALID = -EINVAL,
} MountEntryState;

typedef struct MountEntry {
        const char *path_const;   /* Memory allocated on stack or static */
        MountMode mode;
        bool ignore:1;            /* Ignore if path does not exist? */
        bool has_prefix:1;        /* Already prefixed by the root dir? */
        bool read_only:1;         /* Shall this mount point be read-only? */
        bool nosuid:1;            /* Shall set MS_NOSUID on the mount itself */
        bool noexec:1;            /* Shall set MS_NOEXEC on the mount itself */
        bool exec:1;              /* Shall clear MS_NOEXEC on the mount itself */
        bool create_source_dir:1; /* Create the source directory if it doesn't exist - for implicit bind mounts */
        mode_t source_dir_mode;   /* Mode for the source directory, if it is to be created */
        MountEntryState state;    /* Whether it was already processed or skipped */
        char *path_malloc;        /* Use this instead of 'path_const' if we had to allocate memory */
        const char *unprefixed_path_const; /* If the path was amended with a prefix, these will save the original */
        char *unprefixed_path_malloc;
        const char *source_const; /* The source path, for bind mounts or images */
        char *source_malloc;
        const char *options_const;/* Mount options for tmpfs */
        char *options_malloc;
        unsigned long flags;      /* Mount flags used by EMPTY_DIR and TMPFS. Do not include MS_RDONLY here, but please use read_only. */
        unsigned n_followed;
        MountOptions *image_options_const;
        char **overlay_layers;
        VeritySettings verity;
        ImageClass filter_class; /* Used for live updates to skip inapplicable images */
        bool idmapped;
        uid_t idmap_uid;
        gid_t idmap_gid;
} MountEntry;

typedef struct MountList {
        MountEntry *mounts;
        size_t n_mounts;
} MountList;

const char* mount_entry_path(const MountEntry *p);
const char* mount_entry_unprefixed_path(const MountEntry *p);
void mount_entry_consume_prefix(MountEntry *p, char *new_path);
bool mount_entry_read_only(const MountEntry *p);
bool mount_entry_noexec(const MountEntry *p);
bool mount_entry_exec(const MountEntry *p);
const char* mount_entry_source(const MountEntry *p);
const char* mount_entry_options(const MountEntry *p);
void mount_entry_done(MountEntry *p);
void mount_entry_path_debug_string(const char *root, MountEntry *m, char **ret_path);

void mount_list_done(MountList *ml);
MountEntry* mount_list_extend(MountList *ml);

int mount_path_compare(const MountEntry *a, const MountEntry *b);
int prefix_where_needed(MountList *ml, const char *root_directory);

/* Helper struct for naming simplicity and reusability */
typedef struct ImageClassInfo {
        const char *level_env;
        const char *level_env_print;
} ImageClassInfo;

extern const ImageClassInfo image_class_info[_IMAGE_CLASS_MAX];

/* The mount primitives themselves. The caller still drives these; they move behind
 * mount_list_apply() in a later step. */
int bind_mount_device_dir(const char *temporary_mount, const char *dir);
int clone_device_node(const char *node, const char *temporary_mount, bool *make_devnode);
int create_temporary_mount_point(RuntimeScope scope, char **ret);
int mount_bpffs(const MountEntry *m, PidRef *pidref, int socket_fd, int errno_pipe);
int mount_image(
                MountEntry *m,
                const char *root_directory,
                const ImagePolicy *image_policy,
                RuntimeScope runtime_scope);
int mount_private_apivfs(
                const char *fstype,
                const char *entry_path,
                const char *bind_source,
                const char *opts,
                RuntimeScope scope);
void sort_and_drop_unused_mounts(MountList *ml, const char *root_directory);

/* Modes whose implementation belongs to the caller rather than here: the service manager's own
 * filesystems (procfs with its ProtectProc= handling, the private dev/sysfs/cgroup2fs instances),
 * bpffs, and images, all of which need policy this file has no business knowing. Called for those
 * modes only; its return value is the mount's result. */
typedef int (*MountListApplySpecial)(const char *root_directory, MountEntry *m, void *userdata);

/* Applies a single entry. Returns 1 if it should be post-processed (remounted read-only and so on),
 * 0 if it was gracefully skipped. */
int mount_list_apply_one(
                const char *root_directory,
                MountEntry *m,
                MountListApplySpecial apply_special,
                void *userdata);

int mount_list_apply(
                MountList *ml,
                const char *root,
                char **symlinks,
                bool mount_nosuid,
                MountListApplySpecial apply_special,
                void *userdata,
                char **reterr_path);
