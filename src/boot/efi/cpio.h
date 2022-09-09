/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <stdbool.h>
#include <uchar.h>

EFI_STATUS pack_cpio(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *dropin_dir,
                const char16_t *match_suffix,
                const char *target_dir_prefix,
                uint32_t dir_mode,
                uint32_t access_mode,
                const uint32_t tpm_pcr[],
                UINTN n_tpm_pcr,
                const char16_t *tpm_description,
                void **ret_buffer,
                UINTN *ret_buffer_size,
                bool *ret_measured);

EFI_STATUS pack_cpio_literal(
                const void *data,
                size_t data_size,
                const char *target_dir_prefix,
                const char16_t *target_filename,
                uint32_t dir_mode,
                uint32_t access_mode,
                const uint32_t tpm_pcr[],
                UINTN n_tpm_pcr,
                const char16_t *tpm_description,
                void **ret_buffer,
                UINTN *ret_buffer_size,
                bool *ret_measured);
