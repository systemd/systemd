/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "forward.h"

int load_volume_key_empty(const EnrollContext *c, struct crypt_device *cd, struct iovec *ret_vk);
int load_volume_key_keyfile(const EnrollContext *c, struct crypt_device *cd, struct iovec *ret_vk);

int load_volume_key_password(const EnrollContext *c, struct crypt_device *cd, struct iovec *ret_vk);
int enroll_password(const EnrollContext *c, struct crypt_device *cd, const struct iovec *volume_key);
