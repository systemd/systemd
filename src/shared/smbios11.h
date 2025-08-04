/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int read_smbios11_field(unsigned i, size_t max_size, char **ret_data, size_t *ret_size);
