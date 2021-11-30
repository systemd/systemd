/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

EFI_STATUS pack_cpio_relative(
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *match_suffix,
                const CHAR8 *target_dir_prefix,
                UINT32 dir_mode,
                UINT32 access_mode,
                UINTN pcr,
                const CHAR16 *tpm_description,
                void **ret_buffer,
                UINTN *ret_buffer_size);

EFI_STATUS pack_cpio_absolute(
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *source_dir_path,
                const CHAR16 *match_suffix,
                const CHAR8 *target_dir_prefix,
                UINT32 dir_mode,
                UINT32 access_mode,
                UINTN pcr,
                const CHAR16 *tpm_description,
                void **ret_buffer,
                UINTN *ret_buffer_size);
