/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "compress.h"
#include "forward.h"
#include "sha256.h"

typedef enum ImportFlags {
        /* Public Flags (i.e. accessible via D-Bus, must stay stable! */
        IMPORT_FORCE                   = 1 <<  0, /* replace existing image */
        IMPORT_READ_ONLY               = 1 <<  1, /* make generated image read-only */
        IMPORT_PULL_KEEP_DOWNLOAD      = 1 <<  2, /* keep a pristine copy of the downloaded file around */

        /* Private flags */
        IMPORT_BTRFS_SUBVOL            = 1 <<  3, /* tar: preferably create images as btrfs subvols */
        IMPORT_BTRFS_QUOTA             = 1 <<  4, /* tar: set up btrfs quota for new subvolume as child of parent subvolume */
        IMPORT_CONVERT_QCOW2           = 1 <<  5, /* raw: if we detect a qcow2 image, unpack it */
        IMPORT_DIRECT                  = 1 <<  6, /* import without rename games */
        IMPORT_SYNC                    = 1 <<  7, /* fsync() right before we are done */
        IMPORT_FOREIGN_UID             = 1 <<  8, /* tar: go via nsresourced/mountfsd and make owned by foreign UID */
        IMPORT_ZERO_FILL               = 1 <<  9, /* raw: fill up the remainder of the destination range (as defined by offset/size max) with zeroes */

        /* When pulling these flags are defined too */
        IMPORT_PULL_SETTINGS           = 1 << 10, /* download .nspawn settings file */
        IMPORT_PULL_ROOTHASH           = 1 << 11, /* only for raw: download .roothash file for verity */
        IMPORT_PULL_ROOTHASH_SIGNATURE = 1 << 12, /* only for raw: download .roothash.p7s file for verity */
        IMPORT_PULL_VERITY             = 1 << 13, /* only for raw: download .verity file for verity */
        IMPORT_PULL_CHECKSUM_FILE_YES  = 1 << 14, /* only for raw: the main download is a checksum file, regardless of its name */
        IMPORT_PULL_CHECKSUM_FILE_NO   = 1 << 15, /* only for raw: the main download is not a checksum file, regardless of its name */

        /* The supported flags for the tar and raw importing */
        IMPORT_FLAGS_MASK_TAR          = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_BTRFS_SUBVOL|IMPORT_BTRFS_QUOTA|IMPORT_DIRECT|IMPORT_SYNC|IMPORT_FOREIGN_UID,
        IMPORT_FLAGS_MASK_RAW          = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_CONVERT_QCOW2|IMPORT_DIRECT|IMPORT_SYNC|IMPORT_ZERO_FILL,

        /* The supported flags for the tar, raw, oci pulling */
        IMPORT_PULL_FLAGS_MASK_TAR     = IMPORT_FLAGS_MASK_TAR|IMPORT_PULL_KEEP_DOWNLOAD|IMPORT_PULL_SETTINGS,
        IMPORT_PULL_FLAGS_MASK_RAW     = IMPORT_FLAGS_MASK_RAW|IMPORT_PULL_KEEP_DOWNLOAD|IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY|IMPORT_PULL_CHECKSUM_FILE_YES|IMPORT_PULL_CHECKSUM_FILE_NO,
        IMPORT_PULL_FLAGS_MASK_OCI     = IMPORT_FORCE|IMPORT_READ_ONLY|IMPORT_BTRFS_SUBVOL|IMPORT_BTRFS_QUOTA|IMPORT_SYNC|IMPORT_FOREIGN_UID|IMPORT_PULL_SETTINGS,

        _IMPORT_FLAGS_INVALID = -EINVAL,
} ImportFlags;

int import_fork_tar_c(int tree_fd, int userns_fd, PidRef *ret_pid);
int import_fork_tar_x(int tree_fd, int userns_fd, PidRef *ret_pid);

int import_mangle_os_tree_fd(int tree_fd, int userns_fd, ImportFlags flags);
int import_mangle_os_tree(const char *path, int userns_fd, ImportFlags flags);
int import_mangle_os_tree_fd_foreign(int tree_fd, int userns_fd);

bool import_validate_local(const char *name, ImportFlags flags);

int import_allocate_event_with_signals(sd_event **ret);

int import_make_foreign_userns(int *userns_fd);

int import_remove_tree(const char *path, int *userns_fd, ImportFlags flags);

int import_zero_fill(int fd, uint64_t offset, uint64_t size_max, uint64_t skip);

/* Optionally verifies the SHA256 digest of the decoded (i.e. decompressed) data stream, as opposed to the
 * encoded data as downloaded */
typedef struct ImportDigest {
        bool enabled;
        uint8_t expected[SHA256_DIGEST_SIZE];
        struct sha256_ctx ctx;
} ImportDigest;

void import_digest_init(ImportDigest *d, const struct iovec *expected);
void import_digest_reset(ImportDigest *d);
void import_digest_update(ImportDigest *d, const void *p, size_t sz);
int import_digest_verify(ImportDigest *d);

int import_parse_sha256_argument(const char *option, const char *s, struct iovec *checksum);
int import_parse_compression_argument(const char *option, const char *s, Compression *ret);

/* Tracks the time that passed since the first progress report of an operation, and estimates how much time it
 * is likely going to take still, as well as the transfer rate, based on the progress made so far. No estimate
 * is made until the progress settled a bit, i.e. not in the first few seconds. */
typedef struct ImportProgress {
        usec_t start_usec;              /* When we got the first progress report, 0 if not yet */
        usec_t estimate_start_usec;     /* When we got the first progress report used for estimating, 0 if not yet */
        double estimate_start_percent;  /* The progress at that time */
        usec_t rate_start_usec;         /* When we got the first progress report used for the rate, 0 if not yet */
        uint64_t rate_start_bytes;      /* The bytes done at that time */

        /* The state as of the last import_progress_update() call */
        unsigned percent;
        usec_t time_elapsed;
        usec_t time_left;               /* USEC_INFINITY if not known */
        uint64_t done_bytes;            /* UINT64_MAX if not known */
        uint64_t total_bytes;           /* UINT64_MAX if not known */
        uint64_t bytes_per_sec;         /* UINT64_MAX if not known */
} ImportProgress;

/* Takes the progress percentage to report, the progress to base the estimate of the time left on as amount done
 * of total, in whatever unit (total may be UINT64_MAX if no estimate shall be made), and the bytes done of the
 * total bytes (either may be UINT64_MAX if not known). */
void import_progress_update(
                ImportProgress *p,
                unsigned percent,
                uint64_t done,
                uint64_t total,
                uint64_t done_bytes,
                uint64_t total_bytes);

/* Sends X_IMPORT_PROGRESS=, X_IMPORT_TIME_ELAPSED_USEC= and, if known, the estimated total time of the
 * operation as X_IMPORT_TIME_TOTAL_USEC=, as well as X_IMPORT_DONE_BYTES=, X_IMPORT_TOTAL_BYTES= and
 * X_IMPORT_BYTES_PER_SEC= to our supervisor */
void import_progress_notify(const ImportProgress *p);

/* Formats " (… left, …/s)" from the parts that are known. Returns NULL if neither is known (or on OOM, since
 * this is only used to decorate progress output), hence use with strempty(). */
char* import_progress_format(const ImportProgress *p);
