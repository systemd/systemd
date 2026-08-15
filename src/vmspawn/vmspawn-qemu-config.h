/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "macro.h"

/* Helpers for writing QEMU -readconfig INI-style config files.
 *
 * QEMU config format:
 *   [type "id"]
 *     key = "value"
 *
 * Usage:
 *   qemu_config_section(f, "device", "rng0",
 *                       "driver", "virtio-rng-pci",
 *                       "rng", "rng0");
 */

/* Write a single key = "value" pair (for conditional keys added after a section header) */
int qemu_config_key(FILE *f, const char *key, const char *value);

/* Write a single key with a printf-formatted value */
int qemu_config_keyf(FILE *f, const char *key, const char *format, ...) _printf_(3, 4);

/* Write a section header with key-value pairs. Varargs are alternating key, value strings. */
int qemu_config_section_impl(FILE *f, const char *type, const char *id, ...) _sentinel_;
#define qemu_config_section(...) qemu_config_section_impl(__VA_ARGS__, NULL)
