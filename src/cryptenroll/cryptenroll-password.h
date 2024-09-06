/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"

int load_volume_key_password(struct crypt_device *cd, const char* cd_node, void *ret_vk, size_t *ret_vks);
int enroll_password(struct crypt_device *cd, const struct iovec *volume_key);
