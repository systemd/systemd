/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int load_volume_key_fido2(struct crypt_device *cd, const char *cd_node, const char *device, void *ret_vk, size_t *ret_vks);
int enroll_fido2(struct crypt_device *cd, const struct iovec *volume_key, const char *device, Fido2EnrollFlags lock_with, int cred_alg, const char *salt_file, bool parameters_in_header);
