/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

typedef struct Credential {
        char *id;
        void *data;
        size_t size;
} Credential;

void credential_free_all(Credential *creds, size_t n);
