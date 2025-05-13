/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int enroll_pkcs11(struct crypt_device *cd, const struct iovec *volume_key, const char *uri);
