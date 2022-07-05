/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>
#include <uchar.h>

EFI_STATUS pack_cpio(
                EFI_LOADED_IMAGE *loaded_image,
                const char16_t *dropin_dir,
                const char16_t *match_suffix,
                const char *target_dir_prefix,
                uint32_t dir_mode,
                uint32_t access_mode,
                const uint32_t tpm_pcr[],
                UINTN n_tpm_pcr,
                const char16_t *tpm_description,
                void **ret_buffer,
                UINTN *ret_buffer_size);
