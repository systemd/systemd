/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "forward.h"

/* When c->interactive is unset, the generated recovery key is returned via ret_recovery_key
 * instead of being printed to stdout/stderr + rendered as a QR code. */
int enroll_recovery(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key, char **ret_recovery_key);
