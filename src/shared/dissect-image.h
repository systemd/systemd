/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

#include "list.h"
#include "loop-util.h"
#include "macro.h"

typedef struct DissectedImage DissectedImage;
typedef struct DissectedPartition DissectedPartition;
typedef struct DecryptedImage DecryptedImage;
typedef struct MountOptions MountOptions;
typedef struct VeritySettings VeritySettings;

struct DissectedPartition {
        bool found:1;
        bool rw:1;
        int partno;        /* -1 if there was no partition and the images contains a file system directly */
        int architecture;  /* Intended architecture: either native, secondary or unset (-1). */
        sd_id128_t uuid;   /* Partition entry UUID as reported by the GPT */
        char *fstype;
        char *node;
        char *decrypted_node;
        char *decrypted_fstype;
        char *mount_options;
};

typedef enum PartitionDesignator {
        PARTITION_ROOT,
        PARTITION_ROOT_SECONDARY,  /* Secondary architecture */
        PARTITION_USR,
        PARTITION_USR_SECONDARY,
        PARTITION_HOME,
        PARTITION_SRV,
        PARTITION_ESP,
        PARTITION_XBOOTLDR,
        PARTITION_SWAP,
        PARTITION_ROOT_VERITY, /* verity data for the PARTITION_ROOT partition */
        PARTITION_ROOT_SECONDARY_VERITY, /* verity data for the PARTITION_ROOT_SECONDARY partition */
        PARTITION_USR_VERITY,
        PARTITION_USR_SECONDARY_VERITY,
        PARTITION_TMP,
        PARTITION_VAR,
        _PARTITION_DESIGNATOR_MAX,
        _PARTITION_DESIGNATOR_INVALID = -EINVAL,
} PartitionDesignator;

static inline PartitionDesignator PARTITION_VERITY_OF(PartitionDesignator p) {
        switch (p) {

        case PARTITION_ROOT:
                return PARTITION_ROOT_VERITY;

        case PARTITION_ROOT_SECONDARY:
                return PARTITION_ROOT_SECONDARY_VERITY;

        case PARTITION_USR:
                return PARTITION_USR_VERITY;

        case PARTITION_USR_SECONDARY:
                return PARTITION_USR_SECONDARY_VERITY;

        default:
                return _PARTITION_DESIGNATOR_INVALID;
        }
}

typedef enum DissectImageFlags {
        DISSECT_IMAGE_READ_ONLY           = 1 << 0,
        DISSECT_IMAGE_DISCARD_ON_LOOP     = 1 << 1,  /* Turn on "discard" if on a loop device and file system supports it */
        DISSECT_IMAGE_DISCARD             = 1 << 2,  /* Turn on "discard" if file system supports it, on all block devices */
        DISSECT_IMAGE_DISCARD_ON_CRYPTO   = 1 << 3,  /* Turn on "discard" also on crypto devices */
        DISSECT_IMAGE_DISCARD_ANY = DISSECT_IMAGE_DISCARD_ON_LOOP |
                                    DISSECT_IMAGE_DISCARD |
                                    DISSECT_IMAGE_DISCARD_ON_CRYPTO,
        DISSECT_IMAGE_GPT_ONLY            = 1 << 4,  /* Only recognize images with GPT partition tables */
        DISSECT_IMAGE_REQUIRE_ROOT        = 1 << 5,  /* Don't accept disks without root partition (and if no partition table or only single generic partition, assume it's root) */
        DISSECT_IMAGE_MOUNT_ROOT_ONLY     = 1 << 6,  /* Mount only the root and /usr partitions */
        DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY = 1 << 7,  /* Mount only the non-root and non-/usr partitions */
        DISSECT_IMAGE_VALIDATE_OS         = 1 << 8,  /* Refuse mounting images that aren't identifiable as OS images */
        DISSECT_IMAGE_NO_UDEV             = 1 << 9,  /* Don't wait for udev initializing things */
        DISSECT_IMAGE_RELAX_VAR_CHECK     = 1 << 10, /* Don't insist that the UUID of /var is hashed from /etc/machine-id */
        DISSECT_IMAGE_FSCK                = 1 << 11, /* File system check the partition before mounting (no effect when combined with DISSECT_IMAGE_READ_ONLY) */
        DISSECT_IMAGE_NO_PARTITION_TABLE  = 1 << 12, /* Only recognize single file system images */
        DISSECT_IMAGE_VERITY_SHARE        = 1 << 13, /* When activating a verity device, reuse existing one if already open */
        DISSECT_IMAGE_MKDIR               = 1 << 14, /* Make top-level directory to mount right before mounting, if missing */
} DissectImageFlags;

struct DissectedImage {
        bool encrypted:1;
        bool verity:1;     /* verity available and usable */
        bool can_verity:1; /* verity available, but not necessarily used */
        bool single_file_system:1; /* MBR/GPT or single file system */

        DissectedPartition partitions[_PARTITION_DESIGNATOR_MAX];

        char *image_name;
        char *hostname;
        sd_id128_t machine_id;
        char **machine_info;
        char **os_release;
        char **extension_release;
};

struct MountOptions {
        PartitionDesignator partition_designator;
        char *options;
        LIST_FIELDS(MountOptions, mount_options);
};

struct VeritySettings {
        /* Binary root hash for the Verity Merkle tree */
        void *root_hash;
        size_t root_hash_size;

        /* PKCS#7 signature of the above */
        void *root_hash_sig;
        size_t root_hash_sig_size;

        /* Path to the verity data file, if stored externally */
        char *data_path;

        /* PARTITION_ROOT or PARTITION_USR, depending on what these Verity settings are for */
        PartitionDesignator designator;
};

#define VERITY_SETTINGS_DEFAULT {                               \
                .designator = _PARTITION_DESIGNATOR_INVALID     \
        }

MountOptions* mount_options_free_all(MountOptions *options);
DEFINE_TRIVIAL_CLEANUP_FUNC(MountOptions*, mount_options_free_all);
const char* mount_options_from_designator(const MountOptions *options, PartitionDesignator designator);

int probe_filesystem(const char *node, char **ret_fstype);
int dissect_image(int fd, const VeritySettings *verity, const MountOptions *mount_options, DissectImageFlags flags, DissectedImage **ret);
int dissect_image_and_warn(int fd, const char *name, const VeritySettings *verity, const MountOptions *mount_options, DissectImageFlags flags, DissectedImage **ret);

DissectedImage* dissected_image_unref(DissectedImage *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(DissectedImage*, dissected_image_unref);

int dissected_image_decrypt(DissectedImage *m, const char *passphrase, const VeritySettings *verity, DissectImageFlags flags, DecryptedImage **ret);
int dissected_image_decrypt_interactively(DissectedImage *m, const char *passphrase, const VeritySettings *verity, DissectImageFlags flags, DecryptedImage **ret);
int dissected_image_mount(DissectedImage *m, const char *dest, uid_t uid_shift, DissectImageFlags flags);
int dissected_image_mount_and_warn(DissectedImage *m, const char *where, uid_t uid_shift, DissectImageFlags flags);

int dissected_image_acquire_metadata(DissectedImage *m);

DecryptedImage* decrypted_image_unref(DecryptedImage *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(DecryptedImage*, decrypted_image_unref);
int decrypted_image_relinquish(DecryptedImage *d);

const char* partition_designator_to_string(PartitionDesignator d) _const_;
PartitionDesignator partition_designator_from_string(const char *name) _pure_;

int verity_settings_load(VeritySettings *verity, const char *image, const char *root_hash_path, const char *root_hash_sig_path);
void verity_settings_done(VeritySettings *verity);

bool dissected_image_can_do_verity(const DissectedImage *image, PartitionDesignator d);
bool dissected_image_has_verity(const DissectedImage *image, PartitionDesignator d);

int mount_image_privately_interactively(const char *path, DissectImageFlags flags, char **ret_directory, LoopDevice **ret_loop_device, DecryptedImage **ret_decrypted_image);

int verity_dissect_and_mount(const char *src, const char *dest, const MountOptions *options, const char *required_host_os_release_id, const char *required_host_os_release_version_id, const char *required_host_os_release_sysext_level);
