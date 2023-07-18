/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct UdevEvent UdevEvent;

#define UDEV_ALLOWED_CHARS_INPUT        "/ $%?,"

size_t udev_event_apply_format(
                UdevEvent *event,
                const char *src,
                char *dest,
                size_t size,
                bool replace_whitespace,
                bool *ret_truncated);
int udev_check_format(const char *value, size_t *offset, const char **hint);

int udev_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, bool read_value);
