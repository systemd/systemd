/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "cryptsetup-util.h"
#include "libsss-util.h"
#include "log.h"
#include "time-util.h"

int find_passphrase_auto_data(
                Factor *factors,
                Factor *factor_list,
                uint16_t factor_number,
                struct crypt_device *cd,
                unsigned char **ret_encrypted_share,
                int *ret_keyslot);
