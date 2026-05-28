/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "shared-forward.h"

int enroll_pkcs11(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key);
