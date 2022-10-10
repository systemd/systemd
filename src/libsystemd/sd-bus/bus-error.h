/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "errno-util.h"
#include "macro.h"

bool bus_error_is_dirty(sd_bus_error *e);

const char* _bus_error_message(const sd_bus_error *e, int error, char buf[static ERRNO_BUF_LEN]);

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define bus_error_message(e, error) _bus_error_message(e, error, (char[ERRNO_BUF_LEN]){})

#define BUS_ERROR_OOM SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_MEMORY, "Out of memory")
#define BUS_ERROR_FAILED SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_FAILED, "Operation failed")

/*
 * There are two ways to register error maps with the error translation
 * logic: by using BUS_ERROR_MAP_ELF_REGISTER, which however only
 * works when linked into the same ELF module, or via
 * sd_bus_error_add_map() which is the official, external API, that
 * works from any module.
 *
 * Note that BUS_ERROR_MAP_ELF_REGISTER has to be used as decorator in
 * the bus error table, and BUS_ERROR_MAP_ELF_USE has to be used at
 * least once per compilation unit (i.e. per library), to ensure that
 * the error map is really added to the final binary.
 *
 * In addition, set the retain attribute so that the section cannot be
 * discarded by ld --gc-sections -z start-stop-gc. Older compilers would
 * warn for the unknown attribute, so just disable -Wattributes.
 */

#define BUS_ERROR_MAP_ELF_REGISTER                                      \
        _Pragma("GCC diagnostic ignored \"-Wattributes\"")              \
        _section_("SYSTEMD_BUS_ERROR_MAP")                              \
        _used_                                                          \
        _retain_                                                        \
        _alignptr_                                                      \
        _variable_no_sanitize_address_

#define BUS_ERROR_MAP_ELF_USE(errors)                                   \
        extern const sd_bus_error_map errors[];                         \
        _used_                                                          \
        static const sd_bus_error_map * const CONCATENATE(errors ## _copy_, __COUNTER__) = errors;

/* We use something exotic as end marker, to ensure people build the
 * maps using the macsd-ros. */
#define BUS_ERROR_MAP_END_MARKER -'x'

BUS_ERROR_MAP_ELF_USE(bus_standard_errors);
