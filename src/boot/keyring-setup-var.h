/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define KEYRING_SETUP_NAME_PREFIX "keyring-setup."

/* The smallest valid record: the prefix plus one character, NUL, the length field, one byte of data */
#define KEYRING_SETUP_RECORD_SIZE_MIN (sizeof(KEYRING_SETUP_NAME_PREFIX) + 1 + sizeof(uint32_t) + 1)

/* The largest payload we accept */
#define KEYRING_SETUP_SIZE_MAX (64U*1024U)

bool keyring_setup_credential_name_is_valid(const char *name);

EFI_STATUS keyring_setup_validate(const void *data, size_t size, size_t *ret_n_records);

EFI_STATUS keyring_setup_next_record(
                const void *data,
                size_t size,
                size_t *offset,
                const char **ret_name,
                const void **ret_payload,
                size_t *ret_payload_size);
