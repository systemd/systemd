/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-bus.h"

#include "macro.h"
#include "set.h"

typedef int (*bus_message_print_t) (const char *name, const char *expected_value, sd_bus_message *m, bool value, bool all);

int bus_print_property_value(const char *name, const char *expected_value, bool only_value, const char *value);
int bus_print_property_valuef(const char *name, const char *expected_value, bool only_value, const char *fmt, ...) _printf_(4,5);
int bus_message_print_all_properties(sd_bus_message *m, bus_message_print_t func, char **filter, bool value, bool all, Set **found_properties);
int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path, bus_message_print_t func, char **filter, bool value, bool all, Set **found_properties);
