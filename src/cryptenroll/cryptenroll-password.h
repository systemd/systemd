/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "libsss-util.h"
#include "cryptsetup-util.h"

int enroll_password(struct crypt_device *cd, const void *volume_key, size_t volume_key_size, Factor *factor, int keyslot);
