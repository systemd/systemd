/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int acpi_get_boot_usec(usec_t *ret_loader_start, usec_t *ret_loader_exit);
