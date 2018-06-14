/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2013 Kay Sievers
***/

#include <time-util.h>

int acpi_get_boot_usec(usec_t *loader_start, usec_t *loader_exit);
