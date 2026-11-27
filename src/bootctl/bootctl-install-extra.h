/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bootctl-install.h"
#include "forward.h"
#include "sha256.h"

/* bootctl copies the contents of this directory into the ESP in addition to systemd-boot. */
#define EXTRA_FILES_DIR_NAME "extra"
#define EXTRA_FILES_DIR BOOTLIBDIR "/" EXTRA_FILES_DIR_NAME

/* bootctl lists the systemd-boot binaries and the extra files that it installed in INSTALL_MANIFEST_NAME in
 * the ESP, as a UAPI.16 File Manifest. A UAPI.16 manifest lists every path only once.
 * INSTALL_MANIFEST_PENDING_NAME hence lists the extra files that bootctl is about to copy or could not copy,
 * for which it is unknown whether the old or the new version is in the ESP. */
#define INSTALL_MANIFEST_DIR "EFI/systemd"
#define INSTALL_MANIFEST_NAME "installed.Uapi16Manifest"
#define INSTALL_MANIFEST_PENDING_NAME "installed-pending.Uapi16Manifest"

#define EXTRA_FILES_MAX 128U
#define EXTRA_FILES_DEPTH_MAX 8U

typedef enum ExtraAction {
        EXTRA_ACTION_SKIP,   /* bootctl does not manage the file in the ESP and leaves it alone. */
        EXTRA_ACTION_KEEP,   /* bootctl manages the file in the ESP and does not replace it. */
        EXTRA_ACTION_COPY,
        EXTRA_ACTION_FAILED,
} ExtraAction;

struct ExtraFile {
        char *path;        /* The path is relative to the root of the ESP. */
        char *source_path; /* The source path is NULL for an entry that was read from the manifest. */
        int source_fd;
        uint8_t hash[SHA256_DIGEST_SIZE];
        bool pending;      /* INSTALL_MANIFEST_PENDING_NAME lists the entry. */
        ExtraAction action;
        bool dest_managed;                     /* The file exists in the ESP and bootctl manages it. */
        uint8_t dest_hash[SHA256_DIGEST_SIZE]; /* dest_hash is only valid if dest_managed is set. */
};

void extra_file_array_free(ExtraFile *files, size_t n);
ExtraFile* extra_file_find(ExtraFile *files, size_t n, const char *path);
void extra_manifest_forget(InstallContext *c, const char *path);
bool extra_manifest_lists(InstallContext *c, const char *path, const uint8_t hash[static SHA256_DIGEST_SIZE]);
int install_extra_files(InstallContext *c, const char *arch, bool update_variables);
int load_extra_files(InstallContext *c);
int load_extra_manifest(InstallContext *c);
int remove_extra_files(InstallContext *c);
