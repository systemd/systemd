/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once

#include "efi.h"

EFI_STATUS hwid_match(const void *hwids_buffer, size_t hwids_length, char *const *compatible);
