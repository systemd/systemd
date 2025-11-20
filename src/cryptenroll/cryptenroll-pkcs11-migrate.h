/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

struct crypt_device;

int migrate_pkcs11_to_oaep(struct crypt_device *cd);