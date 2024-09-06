/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* for more information see libcryptsetup.h crypt-tokens section */

const char* cryptsetup_token_version(void);

int cryptsetup_token_open(struct crypt_device *cd, int token,
        char **password, size_t *password_len, void *usrptr);

int cryptsetup_token_open_pin(struct crypt_device *cd, int token,
        const char *pin, size_t pin_size,
        char **password, size_t *password_len, void *usrptr);

void cryptsetup_token_dump(struct crypt_device *cd, const char *json);

int cryptsetup_token_validate(struct crypt_device *cd, const char *json);

void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len);
