/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "import-util.h"
#include "pull-job.h"

typedef enum PullFlags {
        PULL_FORCE              = 1 << 0, /* replace existing image */
        PULL_READ_ONLY          = 1 << 1, /* make generated image read-only */
        PULL_SETTINGS           = 1 << 2, /* download .nspawn settings file */
        PULL_ROOTHASH           = 1 << 3, /* only for raw: download .roothash file for verity */
        PULL_ROOTHASH_SIGNATURE = 1 << 4, /* only for raw: download .roothash.p7s file for verity */
        PULL_VERITY             = 1 << 5, /* only for raw: download .verity file for verity */
        PULL_BTRFS_SUBVOL       = 1 << 6, /* tar: preferably create images as btrfs subvols */
        PULL_BTRFS_QUOTA        = 1 << 7, /* tar: set up btrfs quota for new subvolume as child of parent subvolume */
        PULL_CONVERT_QCOW2      = 1 << 8, /* raw: if we detect a qcow2 image, unpack it */
        PULL_DIRECT             = 1 << 9, /* download without rename games */
        PULL_SYNC               = 1 << 10, /* fsync() right before we are done */

        /* The supported flags for the tar and the raw pulling */
        PULL_FLAGS_MASK_TAR     = PULL_FORCE|PULL_READ_ONLY|PULL_SETTINGS|PULL_BTRFS_SUBVOL|PULL_BTRFS_QUOTA|PULL_DIRECT|PULL_SYNC,
        PULL_FLAGS_MASK_RAW     = PULL_FORCE|PULL_READ_ONLY|PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY|PULL_CONVERT_QCOW2|PULL_DIRECT|PULL_SYNC,
} PullFlags;

int pull_find_old_etags(const char *url, const char *root, int dt, const char *prefix, const char *suffix, char ***etags);

int pull_make_path(const char *url, const char *etag, const char *image_root, const char *prefix, const char *suffix, char **ret);

int pull_make_auxiliary_job(PullJob **ret, const char *url, int (*strip_suffixes)(const char *name, char **ret), const char *suffix, ImportVerify verify, CurlGlue *glue, PullJobOpenDisk on_open_disk, PullJobFinished on_finished, void *userdata);
int pull_make_verification_jobs(PullJob **ret_checksum_job, PullJob **ret_signature_job, ImportVerify verify, const char *checksum, const char *url, CurlGlue *glue, PullJobFinished on_finished, void *userdata);

int pull_verify(ImportVerify verify, const char *checksum, PullJob *main_job, PullJob *checksum_job, PullJob *signature_job, PullJob *settings_job, PullJob *roothash_job, PullJob *roothash_signature_job, PullJob *verity_job);

typedef enum VerificationStyle {
        VERIFICATION_PER_FILE,      /* SuSE-style ".sha256" files with inline gpg signature */
        VERIFICATION_PER_DIRECTORY, /* Ubuntu-style SHA256SUM files with detached SHA256SUM.gpg signatures */
        _VERIFICATION_STYLE_MAX,
        _VERIFICATION_STYLE_INVALID = -EINVAL,
} VerificationStyle;

int verification_style_from_url(const char *url, VerificationStyle *style);

int pull_job_restart_with_sha256sum(PullJob *job, char **ret);

bool pull_validate_local(const char *name, PullFlags flags);

int pull_url_needs_checksum(const char *url);
