/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2016 Djalal Harouni
***/

#include "core-forward.h"
#include "runtime-scope.h"

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

typedef enum PrivateBPF {
        PRIVATE_BPF_NO,
        PRIVATE_BPF_YES,
        _PRIVATE_BPF_MAX,
        _PRIVATE_BPF_INVALID = -EINVAL,
} PrivateBPF;

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
        PRIVATE_USERS_MANAGED,
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

typedef struct PinnedResource {
        /* Pins a disk image, directory or mstack by file descriptors. The paths are stored too, but they are
         * intended to be decoration only, to enhance log messages and should not be load-bearing
         * otherwise. */
        int directory_fd;
        char *directory;
        int image_fd;
        char *image;
        MStack *mstack_loaded;
        char *mstack;
} PinnedResource;

#define PINNED_RESOURCE_NULL                    \
        (PinnedResource) {                      \
                .directory_fd = -EBADF,         \
                .image_fd = -EBADF,             \
        }

typedef struct BindMount {
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
} BindMount;

typedef struct TemporaryFileSystem {
        char *path;
        char *options;
} TemporaryFileSystem;

typedef enum MountImageType {
        MOUNT_IMAGE_DISCRETE,
        MOUNT_IMAGE_EXTENSION,
        _MOUNT_IMAGE_TYPE_MAX,
        _MOUNT_IMAGE_TYPE_INVALID = -EINVAL,
} MountImageType;

typedef struct MountImage {
        char *source;
        char *destination; /* Unused if MountImageType == MOUNT_IMAGE_EXTENSION */
        MountOptions *mount_options;
        bool ignore_enoent;
        MountImageType type;
} MountImage;

typedef struct NamespaceParameters {
        RuntimeScope runtime_scope;

        const PinnedResource *rootfs;
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
        PrivateBPF private_bpf;
        PrivateTmp private_tmp;
        PrivateTmp private_var_tmp;
        PrivatePIDs private_pids;
        PrivateUsers private_users;

        PidRef *bpffs_pidref;
        int bpffs_socket_fd;
        int bpffs_errno_pipe;

        sd_varlink *mountfsd_link;
} NamespaceParameters;

int setup_namespace(const NamespaceParameters *p, char **reterr_path);

#define RUN_SYSTEMD_EMPTY "/run/systemd/empty"

char* namespace_cleanup_tmpdir(char *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, namespace_cleanup_tmpdir);

int setup_tmp_dir_one(const char *id, const char *prefix, char **ret_path);

int setup_shareable_ns(int ns_storage_socket[static 2], unsigned long nsflag);
int open_shareable_ns_path(int netns_storage_socket[static 2], const char *path, unsigned long nsflag);

DECLARE_STRING_TABLE_LOOKUP(protect_home, ProtectHome);

DECLARE_STRING_TABLE_LOOKUP(protect_hostname, ProtectHostname);

DECLARE_STRING_TABLE_LOOKUP(protect_system, ProtectSystem);

DECLARE_STRING_TABLE_LOOKUP(protect_proc, ProtectProc);

DECLARE_STRING_TABLE_LOOKUP(proc_subset, ProcSubset);

DECLARE_STRING_TABLE_LOOKUP(private_bpf, PrivateBPF);

DECLARE_STRING_TABLE_LOOKUP(bpf_delegate_cmd, uint64_t);

DECLARE_STRING_TABLE_LOOKUP(bpf_delegate_map_type, uint64_t);

DECLARE_STRING_TABLE_LOOKUP(bpf_delegate_prog_type, uint64_t);

DECLARE_STRING_TABLE_LOOKUP(bpf_delegate_attach_type, uint64_t);

char* bpf_delegate_to_string(uint64_t u, const char * (*parser)(uint64_t) _const_);
int bpf_delegate_from_string(const char *s, uint64_t *ret, uint64_t (*parser)(const char *));

static inline int bpf_delegate_commands_from_string(const char *s, uint64_t *ret) {
        return bpf_delegate_from_string(s, ret, bpf_delegate_cmd_from_string);
}

static inline char * bpf_delegate_commands_to_string(uint64_t u) {
        return bpf_delegate_to_string(u, bpf_delegate_cmd_to_string);
}

static inline int bpf_delegate_maps_from_string(const char *s, uint64_t *ret) {
        return bpf_delegate_from_string(s, ret, bpf_delegate_map_type_from_string);
}

static inline char * bpf_delegate_maps_to_string(uint64_t u) {
        return bpf_delegate_to_string(u, bpf_delegate_map_type_to_string);
}

static inline int bpf_delegate_programs_from_string(const char *s, uint64_t *ret) {
        return bpf_delegate_from_string(s, ret, bpf_delegate_prog_type_from_string);
}

static inline char * bpf_delegate_programs_to_string(uint64_t u) {
        return bpf_delegate_to_string(u, bpf_delegate_prog_type_to_string);
}

static inline int bpf_delegate_attachments_from_string(const char *s, uint64_t *ret) {
        return bpf_delegate_from_string(s, ret, bpf_delegate_attach_type_from_string);
}

static inline char * bpf_delegate_attachments_to_string(uint64_t u) {
        return bpf_delegate_to_string(u, bpf_delegate_attach_type_to_string);
}

DECLARE_STRING_TABLE_LOOKUP(private_tmp, PrivateTmp);

DECLARE_STRING_TABLE_LOOKUP(private_users, PrivateUsers);

DECLARE_STRING_TABLE_LOOKUP(protect_control_groups, ProtectControlGroups);

DECLARE_STRING_TABLE_LOOKUP(private_pids, PrivatePIDs);

void bind_mount_free_many(BindMount *b, size_t n);
int bind_mount_add(BindMount **b, size_t *n, const BindMount *item);

void mount_image_free_many(MountImage *m, size_t n);
int mount_image_add(MountImage **m, size_t *n, const MountImage *item);

void temporary_filesystem_free_many(TemporaryFileSystem *t, size_t n);
int temporary_filesystem_add(
                TemporaryFileSystem **t,
                size_t *n,
                const char *path,
                const char *options);

int refresh_extensions_in_namespace(
                const PidRef *target,
                const char *hierarchy_env,
                const NamespaceParameters *p);

void pinned_resource_done(PinnedResource *p);
bool pinned_resource_is_set(const PinnedResource *p);
