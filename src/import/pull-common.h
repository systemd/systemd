/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "import-util.h"
#include "pull-job.h"

typedef enum PullFlags {
        PULL_FORCE              = 1 << 0,  /* replace existing image */
        PULL_SETTINGS           = 1 << 1,  /* .nspawn settings file */
        PULL_ROOTHASH           = 1 << 2,  /* only for raw: .roothash file for verity */
        PULL_ROOTHASH_SIGNATURE = 1 << 3,  /* only for raw: .roothash.p7s file for verity */
        PULL_VERITY             = 1 << 4,  /* only for raw: .verity file for verity */

        /* The supported flags for the tar and the raw pulling */
        PULL_FLAGS_MASK_TAR     = PULL_FORCE|PULL_SETTINGS,
        PULL_FLAGS_MASK_RAW     = PULL_FORCE|PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY,
} PullFlags;

int pull_make_local_copy(const char *final, const char *root, const char *local, PullFlags flags);

int pull_find_old_etags(const char *url, const char *root, int dt, const char *prefix, const char *suffix, char ***etags);

int pull_make_path(const char *url, const char *etag, const char *image_root, const char *prefix, const char *suffix, char **ret);

int pull_make_auxiliary_job(PullJob **ret, const char *url, int (*strip_suffixes)(const char *name, char **ret), const char *suffix, CurlGlue *glue, PullJobFinished on_finished, void *userdata);
int pull_make_verification_jobs(PullJob **ret_checksum_job, PullJob **ret_signature_job, ImportVerify verify, const char *url, CurlGlue *glue, PullJobFinished on_finished, void *userdata);

int pull_verify(ImportVerify verify, PullJob *main_job, PullJob *checksum_job, PullJob *signature_job, PullJob *settings_job, PullJob *roothash_job, PullJob *roothash_signature_job, PullJob *verity_job);

typedef enum VerificationStyle {
        VERIFICATION_PER_FILE,      /* SuSE-style ".sha256" files with inline gpg signature */
        VERIFICATION_PER_DIRECTORY, /* Ubuntu-style SHA256SUM files with detached SHA256SUM.gpg signatures */
        _VERIFICATION_STYLE_MAX,
        _VERIFICATION_STYLE_INVALID = -EINVAL,
} VerificationStyle;

int verification_style_from_url(const char *url, VerificationStyle *style);

int pull_job_restart_with_sha256sum(PullJob *job, char **ret);
