/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "macro.h"
#include "memory-util.h"
#include "nspawn-creds.h"

static void credential_free(Credential *cred) {
        assert(cred);

        cred->id = mfree(cred->id);
        cred->data = erase_and_free(cred->data);
        cred->size = 0;
}

void credential_free_all(Credential *creds, size_t n) {
        size_t i;

        assert(creds || n == 0);

        for (i = 0; i < n; i++)
                credential_free(creds + i);

        free(creds);
}
