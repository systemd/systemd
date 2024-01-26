/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "varlink.h"

int enroll_recovery(struct crypt_device *cd, const void *volume_key, size_t volume_key_size);
int vl_method_enroll_recovery(Varlink *link, JsonVariant *params, VarlinkMethodFlags flags, void *userdata);
