/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "shared-forward.h"

typedef struct EnrolledSlot {
        int slot;
        /* The token type associated with the slot. ENROLL_PASSWORD means a bare passphrase slot without
         * any token. _ENROLL_TYPE_INVALID means either a token of an unrecognized type, or a slot claimed
         * by more than one token (see 'conflict'). */
        EnrollType type;
        bool conflict;
} EnrolledSlot;

/* Enumerates the active keyslots and classifies each by token type. Returns a newly allocated array. */
int collect_enrolled_slots(struct crypt_device *cd, EnrolledSlot **ret, size_t *ret_n);

int list_enrolled(struct crypt_device *cd);
