/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "forward.h"

int load_volume_key_fido2(const EnrollContext *c, struct crypt_device *cd, struct iovec *ret_vk);
int enroll_fido2(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key);
