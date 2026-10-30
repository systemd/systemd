/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Helpers for small files in /run/ that contain a 64-bit version field followed by raw 64-bit
 * counters. Daemons map these for their whole runtime, so that the counters survive restarts of the
 * daemon, but are reset on reboot. The format is native endian and not a stable interface. */

int counters_file_map(const char *path, size_t size, uint64_t version, void **ret);
