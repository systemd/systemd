/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

int is_fido_security_token_desc(const uint8_t *desc, size_t desc_len);
