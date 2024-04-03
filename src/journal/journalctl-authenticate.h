/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_GCRYPT

int action_setup_keys(void);

#else

#include "log.h"

static inline int action_setup_keys(void) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Forward-secure sealing not available.");
}

#endif
