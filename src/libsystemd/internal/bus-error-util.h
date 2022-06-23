/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"

#define BUS_ERROR_OOM SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_MEMORY, "Out of memory")
#define BUS_ERROR_FAILED SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FAILED, "Operation failed")

const char* bus_error_message(const sd_bus_error *e, int error);

BUS_ERROR_MAP_ELF_USE(bus_standard_errors);
