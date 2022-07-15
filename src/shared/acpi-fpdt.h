/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <time-util.h>

int acpi_get_boot_usec(usec_t *loader_start, usec_t *loader_exit);
