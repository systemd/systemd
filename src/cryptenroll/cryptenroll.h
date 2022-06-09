/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include "libsss-util.h"

typedef enum WipeScope {
        WIPE_EXPLICIT,          /* only wipe the listed slots */
        WIPE_ALL,               /* wipe all slots */
        WIPE_EMPTY_PASSPHRASE,  /* wipe slots with empty passphrases plus listed slots */
        _WIPE_SCOPE_MAX,
        _WIPE_SCOPE_INVALID = -EINVAL,
} WipeScope;

const char* enroll_type_to_string(EnrollType t);
EnrollType enroll_type_from_string(const char *s);

const char* luks2_token_type_to_string(EnrollType t);
EnrollType luks2_token_type_from_string(const char *s);
