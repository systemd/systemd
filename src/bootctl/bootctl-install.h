/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "boot-entry.h"
#include "bootctl.h"
#include "crypto-util.h"
#include "forward.h"

typedef enum InstallOperation {
        INSTALL_NEW,
        INSTALL_UPDATE,
        INSTALL_REMOVE,
        INSTALL_TEST,
        _INSTALL_OPERATION_MAX,
        _INSTALL_OPERATION_INVALID = -1,
} InstallOperation;

typedef struct ExtraFile ExtraFile;

typedef struct InstallContext {
        InstallOperation operation;
        bool graceful;
        char *root;
        int root_fd;
        sd_id128_t machine_id;
        char *install_layout;
        BootEntryTokenType entry_token_type;
        char *entry_token;
        int make_entry_directory; /* tri-state */
        InstallSource install_source;
        char *esp_path;
        int esp_fd;
        uint32_t esp_part;
        uint64_t esp_pstart;
        uint64_t esp_psize;
        sd_id128_t esp_uuid;
        char *xbootldr_path;
        int xbootldr_fd;
#if HAVE_OPENSSL
        X509 *secure_boot_certificate;
        EVP_PKEY *secure_boot_private_key;
#endif
        int touch_variables; /* tri-state */
        DIR *source_dir;            /* source_dir is the BOOTLIBDIR that open_source_directory() selected.
                                     * It is NULL if there is nothing to install. */
        char *source_path;
        bool source_from_image;     /* source_dir is located below c->root_fd and not on the host. */
        bool changed;               /* An extra file or a boot entry was installed or removed. */
        bool extra_manifest_damaged;
        ExtraFile *extra_files;     /* extra_files lists the files below EXTRA_FILES_DIR. */
        size_t n_extra_files;
        ExtraFile *extra_manifest;  /* extra_manifest lists the files that an earlier invocation installed.
                                     * A path is listed once per hash if an earlier invocation was
                                     * interrupted. */
        size_t n_extra_manifest;
        ExtraFile *extra_installed; /* extra_installed lists the files that bootctl manages after
                                     * install_extra_files() ran. */
        size_t n_extra_installed;
} InstallContext;

#define INSTALL_CONTEXT_NULL                                            \
        (InstallContext) {                                              \
                .operation = _INSTALL_OPERATION_INVALID,                \
                .root_fd = -EBADF,                                      \
                .entry_token_type = _BOOT_ENTRY_TOKEN_TYPE_INVALID,     \
                .make_entry_directory = -1,                             \
                .install_source = _INSTALL_SOURCE_INVALID,              \
                .esp_part = UINT32_MAX,                                 \
                .esp_pstart = UINT64_MAX,                               \
                .esp_psize = UINT64_MAX,                                \
                .esp_fd = -EBADF,                                       \
                .xbootldr_fd = -EBADF,                                  \
                .touch_variables = -1,                                  \
        }

int copy_file_with_version_check(
                const char *source_path,
                int source_fd,
                const char *dest_path,
                int dest_parent_fd,
                const char *dest_filename,
                int dest_fd,
                bool force);
int find_slot(sd_id128_t uuid, const char *path, uint16_t *id);

int verb_install(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_remove(int argc, char *argv[], uintptr_t _data, void *userdata);
int verb_is_installed(int argc, char *argv[], uintptr_t _data, void *userdata);

int vl_method_install(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
