/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum BusPrintPropertyFlags {
        BUS_PRINT_PROPERTY_ONLY_VALUE = 1 << 0,  /* e.g. systemctl --value */
        BUS_PRINT_PROPERTY_SHOW_EMPTY = 1 << 1,  /* e.g. systemctl --all */
        BUS_PRINT_PROPERTY_JSON       = 1 << 2,  /* JSON output format */
        BUS_PRINT_PROPERTY_JSON_PRETTY = 1 << 3,  /* Pretty JSON output format */
} BusPrintPropertyFlags;

typedef int (*bus_message_print_t) (const char *name, const char *expected_value, sd_bus_message *m, BusPrintPropertyFlags flags);

int bus_print_property_value(const char *name, const char *expected_value, BusPrintPropertyFlags flags, const char *value);
int bus_print_property_valuef(const char *name, const char *expected_value, BusPrintPropertyFlags flags, const char *fmt, ...) _printf_(4,5);
void bus_print_property_json_finish(BusPrintPropertyFlags flags);
int bus_message_print_all_properties(sd_bus_message *m, bus_message_print_t func, char **filter, BusPrintPropertyFlags flags, Set **found_properties);
int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path, bus_message_print_t func, char **filter, BusPrintPropertyFlags flags, sd_bus_error *reterr_error);
