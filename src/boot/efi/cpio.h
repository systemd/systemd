/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS pack_cpio(
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *dropin_dir,
                const CHAR16 *match_suffix,
                const CHAR8 *target_dir_prefix,
                uint32_t dir_mode,
                uint32_t access_mode,
                const uint32_t tpm_pcr[],
                UINTN n_tpm_pcr,
                const CHAR16 *tpm_description,
                void **ret_buffer,
                UINTN *ret_buffer_size);
