/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

#include "macro.h"

typedef struct DissectedImage DissectedImage;
typedef struct DissectedPartition DissectedPartition;
typedef struct DecryptedImage DecryptedImage;

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
};

enum  {
        PARTITION_ROOT,
        PARTITION_ROOT_SECONDARY,  /* Secondary architecture */
        PARTITION_HOME,
        PARTITION_SRV,
        PARTITION_ESP,
        PARTITION_SWAP,
        PARTITION_ROOT_VERITY, /* verity data for the PARTITION_ROOT partition */
        PARTITION_ROOT_SECONDARY_VERITY, /* verity data for the PARTITION_ROOT_SECONDARY partition */
        _PARTITION_DESIGNATOR_MAX,
        _PARTITION_DESIGNATOR_INVALID = -1
};

static inline int PARTITION_VERITY_OF(int p) {
        if (p == PARTITION_ROOT)
                return PARTITION_ROOT_VERITY;
        if (p == PARTITION_ROOT_SECONDARY)
                return PARTITION_ROOT_SECONDARY_VERITY;
        return _PARTITION_DESIGNATOR_INVALID;
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
        DISSECT_IMAGE_REQUIRE_ROOT        = 1 << 5,  /* Don't accept disks without root partition */
        DISSECT_IMAGE_MOUNT_ROOT_ONLY     = 1 << 6,  /* Mount only the root partition */
        DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY = 1 << 7,  /* Mount only non-root partitions */
        DISSECT_IMAGE_VALIDATE_OS         = 1 << 8,  /* Refuse mounting images that aren't identifyable as OS images */
} DissectImageFlags;

struct DissectedImage {
        bool encrypted:1;
        bool verity:1;     /* verity available and usable */
        bool can_verity:1; /* verity available, but not necessarily used */

        DissectedPartition partitions[_PARTITION_DESIGNATOR_MAX];

        char *hostname;
        sd_id128_t machine_id;
        char **machine_info;
        char **os_release;
};

int probe_filesystem(const char *node, char **ret_fstype);
int dissect_image(int fd, const void *root_hash, size_t root_hash_size, DissectImageFlags flags, DissectedImage **ret);
int dissect_image_and_warn(int fd, const char *name, const void *root_hash, size_t root_hash_size, DissectImageFlags flags, DissectedImage **ret);

DissectedImage* dissected_image_unref(DissectedImage *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(DissectedImage*, dissected_image_unref);

int dissected_image_decrypt(DissectedImage *m, const char *passphrase, const void *root_hash, size_t root_hash_size, DissectImageFlags flags, DecryptedImage **ret);
int dissected_image_decrypt_interactively(DissectedImage *m, const char *passphrase, const void *root_hash, size_t root_hash_size, DissectImageFlags flags, DecryptedImage **ret);
int dissected_image_mount(DissectedImage *m, const char *dest, uid_t uid_shift, DissectImageFlags flags);

int dissected_image_acquire_metadata(DissectedImage *m);

DecryptedImage* decrypted_image_unref(DecryptedImage *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(DecryptedImage*, decrypted_image_unref);
int decrypted_image_relinquish(DecryptedImage *d);

const char* partition_designator_to_string(int i) _const_;
int partition_designator_from_string(const char *name) _pure_;

int root_hash_load(const char *image, void **ret, size_t *ret_size);
