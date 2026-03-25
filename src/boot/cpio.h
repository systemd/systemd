/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"
#include "proto/loaded-image.h"

typedef struct CpioTarget {
        const char *directory; /* Path to directory where to place resources */
        uint32_t dir_mode;     /* Access mode for the directory */
        uint32_t access_mode;  /* Access mode for the files in the directory */
} CpioTarget;

EFI_STATUS pack_cpio_one(
                const char16_t *fname,
                const void *contents,
                size_t contents_size,
                const CpioTarget *target,
                uint32_t *inode_counter,
                void **cpio_buffer,
                size_t *cpio_buffer_size);

EFI_STATUS pack_cpio_prefix(
                const CpioTarget *target,
                uint32_t *inode_counter,
                void **cpio_buffer,
                size_t *cpio_buffer_size);

EFI_STATUS pack_cpio_trailer(
                void **cpio_buffer,
                size_t *cpio_buffer_size);

EFI_STATUS pack_cpio(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *dropin_dir,
                const char16_t *match_suffix,
                const char16_t *exclude_suffix,
                const CpioTarget *target,
                uint32_t tpm_pcr,
                const char16_t *tpm_description,
                struct iovec *ret_buffer,
                bool *ret_measured);

EFI_STATUS pack_cpio_literal(
                const void *data,
                size_t data_size,
                const CpioTarget *target,
                const char16_t *target_filename,
                uint32_t tpm_pcr,
                const char16_t *tpm_description,
                struct iovec *ret_buffer,
                bool *ret_measured);

extern const CpioTarget cpio_target_credentials;
extern const CpioTarget cpio_target_global_credentials;
extern const CpioTarget cpio_target_sysext;
extern const CpioTarget cpio_target_global_sysext;
extern const CpioTarget cpio_target_confext;
extern const CpioTarget cpio_target_global_confext;
extern const CpioTarget cpio_target_meta;
extern const CpioTarget cpio_target_meta_secret;
