/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"

int enroll_recovery(struct crypt_device *cd, const struct iovec *volume_key);
