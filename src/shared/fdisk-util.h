/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LIBFDISK

#include <libfdisk.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_context*, fdisk_unref_context, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_partition*, fdisk_unref_partition, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_parttype*, fdisk_unref_parttype, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_table*, fdisk_unref_table, NULL);

#endif
