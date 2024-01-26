/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "varlink.h"

int load_volume_key_password(struct crypt_device *cd, const char* cd_node, void *ret_vk, size_t *ret_vks);
int enroll_password(struct crypt_device *cd, const void *volume_key, size_t volume_key_size);

int vl_method_enroll_password(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata);
