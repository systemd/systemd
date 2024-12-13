/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 Djalal Harouni
***/

typedef struct NamespaceParameters NamespaceParameters;
typedef struct BindMount BindMount;
typedef struct TemporaryFileSystem TemporaryFileSystem;
typedef struct MountImage MountImage;

#include <stdbool.h>

#include "dissect-image.h"
#include "fs-util.h"
#include "macro.h"
#include "namespace-util.h"
#include "runtime-scope.h"
#include "string-util.h"

typedef enum ProtectHome {
        PROTECT_HOME_NO,
        PROTECT_HOME_YES,
        PROTECT_HOME_READ_ONLY,
        PROTECT_HOME_TMPFS,
        _PROTECT_HOME_MAX,
        _PROTECT_HOME_INVALID = -EINVAL,
} ProtectHome;

typedef enum ProtectHostname {
        PROTECT_HOSTNAME_NO,
        PROTECT_HOSTNAME_YES,
        PROTECT_HOSTNAME_PRIVATE,
        _PROTECT_HOSTNAME_MAX,
        _PROTECT_HOSTNAME_INVALID = -EINVAL,
} ProtectHostname;

typedef enum ProtectSystem {
        PROTECT_SYSTEM_NO,
        PROTECT_SYSTEM_YES,
        PROTECT_SYSTEM_FULL,
        PROTECT_SYSTEM_STRICT,
        _PROTECT_SYSTEM_MAX,
        _PROTECT_SYSTEM_INVALID = -EINVAL,
} ProtectSystem;

typedef enum ProtectProc {
        PROTECT_PROC_DEFAULT,
        PROTECT_PROC_NOACCESS,   /* hidepid=noaccess */
        PROTECT_PROC_INVISIBLE,  /* hidepid=invisible */
        PROTECT_PROC_PTRACEABLE, /* hidepid=ptraceable */
        _PROTECT_PROC_MAX,
        _PROTECT_PROC_INVALID = -EINVAL,
} ProtectProc;

typedef enum ProcSubset {
        PROC_SUBSET_ALL,
        PROC_SUBSET_PID, /* subset=pid */
        _PROC_SUBSET_MAX,
        _PROC_SUBSET_INVALID = -EINVAL,
} ProcSubset;

typedef enum PrivateTmp {
        PRIVATE_TMP_NO,
        PRIVATE_TMP_CONNECTED, /* Bind mounted from the host's filesystem */
        PRIVATE_TMP_DISCONNECTED, /* A completely private tmpfs, invisible from the host */
        _PRIVATE_TMP_MAX,
        _PRIVATE_TMP_INVALID = -EINVAL,
} PrivateTmp;

typedef enum PrivateUsers {
        PRIVATE_USERS_NO,
        PRIVATE_USERS_SELF,
        PRIVATE_USERS_IDENTITY,
        PRIVATE_USERS_FULL,
        _PRIVATE_USERS_MAX,
        _PRIVATE_USERS_INVALID = -EINVAL,
} PrivateUsers;

typedef enum ProtectControlGroups {
        PROTECT_CONTROL_GROUPS_NO,
        PROTECT_CONTROL_GROUPS_YES,
        PROTECT_CONTROL_GROUPS_PRIVATE,
        PROTECT_CONTROL_GROUPS_STRICT,
        _PROTECT_CONTROL_GROUPS_MAX,
        _PROTECT_CONTROL_GROUPS_INVALID = -EINVAL,
} ProtectControlGroups;

typedef enum PrivatePIDs {
        PRIVATE_PIDS_NO,
        PRIVATE_PIDS_YES,
        _PRIVATE_PIDS_MAX,
        _PRIVATE_PIDS_INVALID = -EINVAL,
} PrivatePIDs;

struct BindMount {
        char *source;
        char *destination;
        bool read_only;
        bool nodev;
        bool nosuid;
        bool noexec;
        bool recursive;
        bool ignore_enoent;
        bool idmapped;
        uid_t uid;
        gid_t gid;
};

struct TemporaryFileSystem {
        char *path;
        char *options;
};

typedef enum MountImageType {
        MOUNT_IMAGE_DISCRETE,
        MOUNT_IMAGE_EXTENSION,
        _MOUNT_IMAGE_TYPE_MAX,
        _MOUNT_IMAGE_TYPE_INVALID = -EINVAL,
} MountImageType;

struct MountImage {
        char *source;
        char *destination; /* Unused if MountImageType == MOUNT_IMAGE_EXTENSION */
        LIST_HEAD(MountOptions, mount_options);
        bool ignore_enoent;
        MountImageType type;
};

struct NamespaceParameters {
        RuntimeScope runtime_scope;

        const char *root_directory;
        const char *root_image;
        const MountOptions *root_image_options;
        const ImagePolicy *root_image_policy;

        char **read_write_paths;
        char **read_only_paths;
        char **inaccessible_paths;

        char **exec_paths;
        char **no_exec_paths;

        char **empty_directories;
        char **symlinks;

        const BindMount *bind_mounts;
        size_t n_bind_mounts;

        const TemporaryFileSystem *temporary_filesystems;
        size_t n_temporary_filesystems;

        const MountImage *mount_images;
        size_t n_mount_images;
        const ImagePolicy *mount_image_policy;

        const char *tmp_dir;
        const char *var_tmp_dir;

        const char *creds_path;
        const char *log_namespace;

        unsigned long mount_propagation_flag;
        VeritySettings *verity;

        const MountImage *extension_images;
        size_t n_extension_images;
        const ImagePolicy *extension_image_policy;
        char **extension_directories;

        const char *propagate_dir;
        const char *incoming_dir;

        const char *private_namespace_dir;
        const char *host_notify_socket;
        const char *notify_socket_path;
        const char *host_os_release_stage;

        bool ignore_protect_paths;

        bool protect_kernel_tunables;
        bool protect_kernel_modules;
        bool protect_kernel_logs;

        bool private_dev;
        bool private_network;
        bool private_ipc;

        bool mount_apivfs;
        bool bind_log_sockets;
        bool mount_nosuid;

        ProtectControlGroups protect_control_groups;
        ProtectHome protect_home;
        ProtectHostname protect_hostname;
        ProtectSystem protect_system;
        ProtectProc protect_proc;
        ProcSubset proc_subset;
        PrivateTmp private_tmp;
        PrivatePIDs private_pids;
};

int setup_namespace(const NamespaceParameters *p, char **reterr_path);

#define RUN_SYSTEMD_EMPTY "/run/systemd/empty"

static inline char* namespace_cleanup_tmpdir(char *p) {
        PROTECT_ERRNO;
        if (!streq_ptr(p, RUN_SYSTEMD_EMPTY))
                (void) rmdir(p);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, namespace_cleanup_tmpdir);

int setup_tmp_dirs(
                const char *id,
                char **tmp_dir,
                char **var_tmp_dir);

int setup_shareable_ns(int ns_storage_socket[static 2], unsigned long nsflag);
int open_shareable_ns_path(int netns_storage_socket[static 2], const char *path, unsigned long nsflag);

const char* protect_home_to_string(ProtectHome p) _const_;
ProtectHome protect_home_from_string(const char *s) _pure_;

const char* protect_hostname_to_string(ProtectHostname p) _const_;
ProtectHostname protect_hostname_from_string(const char *s) _pure_;

const char* protect_system_to_string(ProtectSystem p) _const_;
ProtectSystem protect_system_from_string(const char *s) _pure_;

const char* protect_proc_to_string(ProtectProc i) _const_;
ProtectProc protect_proc_from_string(const char *s) _pure_;

const char* proc_subset_to_string(ProcSubset i) _const_;
ProcSubset proc_subset_from_string(const char *s) _pure_;

const char* private_tmp_to_string(PrivateTmp i) _const_;
PrivateTmp private_tmp_from_string(const char *s) _pure_;

const char* private_users_to_string(PrivateUsers i) _const_;
PrivateUsers private_users_from_string(const char *s) _pure_;

const char* protect_control_groups_to_string(ProtectControlGroups i) _const_;
ProtectControlGroups protect_control_groups_from_string(const char *s) _pure_;

const char* private_pids_to_string(PrivatePIDs i) _const_;
PrivatePIDs private_pids_from_string(const char *s) _pure_;

void bind_mount_free_many(BindMount *b, size_t n);
int bind_mount_add(BindMount **b, size_t *n, const BindMount *item);

void temporary_filesystem_free_many(TemporaryFileSystem *t, size_t n);
int temporary_filesystem_add(TemporaryFileSystem **t, size_t *n,
                             const char *path, const char *options);

MountImage* mount_image_free_many(MountImage *m, size_t *n);
int mount_image_add(MountImage **m, size_t *n, const MountImage *item);

const char* namespace_type_to_string(NamespaceType t) _const_;
NamespaceType namespace_type_from_string(const char *s) _pure_;

bool ns_type_supported(NamespaceType type);
