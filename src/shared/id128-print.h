/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stdbool.h>

#include "sd-id128.h"

int id128_pretty_print(sd_id128_t id, bool pretty);
int id128_print_new(bool pretty);
