/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "missing_keyctl.h"

/* TAKE_FD but for key_serial_t instead of fds */
#define TAKE_KEY_SERIAL(key_serial)                             \
        ({                                                      \
                key_serial_t *_key_serialp_ = &(key_serial);    \
                key_serial_t _key_serial_ = *_key_serialp_;     \
                *_key_serialp_ = -1;                            \
                _key_serial_;                                   \
        })

int keyring_read(key_serial_t serial, void **ret, size_t *ret_size);
