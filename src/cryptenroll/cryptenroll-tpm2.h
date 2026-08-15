/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "forward.h"

int load_volume_key_tpm2(const EnrollContext *c, struct crypt_device *cd, struct iovec *ret_vk);
int enroll_tpm2(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key, int *ret_slot_to_wipe);
