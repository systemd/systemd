/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LIBFDISK

#include <libfdisk.h> /* IWYU pragma: export */

#include "forward.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_context*, fdisk_unref_context, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_partition*, fdisk_unref_partition, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_parttype*, fdisk_unref_parttype, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct fdisk_table*, fdisk_unref_table, NULL);

int fdisk_new_context_at(int dir_fd, const char *path, bool read_only, uint32_t sector_size, struct fdisk_context **ret);

int fdisk_partition_get_uuid_as_id128(struct fdisk_partition *p, sd_id128_t *ret);
int fdisk_partition_get_type_as_id128(struct fdisk_partition *p, sd_id128_t *ret);

int fdisk_partition_get_attrs_as_uint64(struct fdisk_partition *pa, uint64_t *ret);
int fdisk_partition_set_attrs_as_uint64(struct fdisk_partition *pa, uint64_t flags);

#endif
