/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "cryptsetup-util.h"

int parse_integrity_options(const char *options, uint32_t *activate_flags, struct crypt_params_integrity *p, char **data_device, char **integrity_algr);
