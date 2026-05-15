/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_LIBFDISK

#include <libfdisk.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(fdisk_add_partition);
extern DLSYM_PROTOTYPE(fdisk_apply_table);
extern DLSYM_PROTOTYPE(fdisk_ask_get_type);
extern DLSYM_PROTOTYPE(fdisk_ask_string_set_result);
extern DLSYM_PROTOTYPE(fdisk_assign_device);
extern DLSYM_PROTOTYPE(fdisk_assign_device_by_fd);
extern DLSYM_PROTOTYPE(fdisk_create_disklabel);
extern DLSYM_PROTOTYPE(fdisk_delete_partition);
extern DLSYM_PROTOTYPE(fdisk_get_devfd);
extern DLSYM_PROTOTYPE(fdisk_get_disklabel_id);
extern DLSYM_PROTOTYPE(fdisk_get_first_lba);
extern DLSYM_PROTOTYPE(fdisk_get_grain_size);
extern DLSYM_PROTOTYPE(fdisk_get_last_lba);
extern DLSYM_PROTOTYPE(fdisk_get_npartitions);
extern DLSYM_PROTOTYPE(fdisk_get_nsectors);
extern DLSYM_PROTOTYPE(fdisk_get_partition);
extern DLSYM_PROTOTYPE(fdisk_get_partitions);
extern DLSYM_PROTOTYPE(fdisk_get_sector_size);
extern DLSYM_PROTOTYPE(fdisk_has_label);
extern DLSYM_PROTOTYPE(fdisk_is_labeltype);
extern DLSYM_PROTOTYPE(fdisk_new_context);
extern DLSYM_PROTOTYPE(fdisk_new_partition);
extern DLSYM_PROTOTYPE(fdisk_new_parttype);
extern DLSYM_PROTOTYPE(fdisk_partname);
extern DLSYM_PROTOTYPE(fdisk_partition_get_attrs);
extern DLSYM_PROTOTYPE(fdisk_partition_get_end);
extern DLSYM_PROTOTYPE(fdisk_partition_get_name);
extern DLSYM_PROTOTYPE(fdisk_partition_get_partno);
extern DLSYM_PROTOTYPE(fdisk_partition_get_size);
extern DLSYM_PROTOTYPE(fdisk_partition_get_start);
extern DLSYM_PROTOTYPE(fdisk_partition_get_type);
extern DLSYM_PROTOTYPE(fdisk_partition_get_uuid);
extern DLSYM_PROTOTYPE(fdisk_partition_has_end);
extern DLSYM_PROTOTYPE(fdisk_partition_has_partno);
extern DLSYM_PROTOTYPE(fdisk_partition_has_size);
extern DLSYM_PROTOTYPE(fdisk_partition_has_start);
extern DLSYM_PROTOTYPE(fdisk_partition_is_used);
extern DLSYM_PROTOTYPE(fdisk_partition_partno_follow_default);
extern DLSYM_PROTOTYPE(fdisk_partition_set_attrs);
extern DLSYM_PROTOTYPE(fdisk_partition_set_name);
extern DLSYM_PROTOTYPE(fdisk_partition_set_partno);
extern DLSYM_PROTOTYPE(fdisk_partition_set_size);
extern DLSYM_PROTOTYPE(fdisk_partition_set_start);
extern DLSYM_PROTOTYPE(fdisk_partition_set_type);
extern DLSYM_PROTOTYPE(fdisk_partition_set_uuid);
extern DLSYM_PROTOTYPE(fdisk_partition_size_explicit);
extern DLSYM_PROTOTYPE(fdisk_partition_to_string);
extern DLSYM_PROTOTYPE(fdisk_parttype_get_string);
extern DLSYM_PROTOTYPE(fdisk_parttype_set_typestr);
extern DLSYM_PROTOTYPE(fdisk_ref_partition);
extern DLSYM_PROTOTYPE(fdisk_save_user_sector_size);
extern DLSYM_PROTOTYPE(fdisk_set_ask);
extern DLSYM_PROTOTYPE(fdisk_set_disklabel_id);
extern DLSYM_PROTOTYPE(fdisk_set_partition);
extern DLSYM_PROTOTYPE(fdisk_table_get_nents);
extern DLSYM_PROTOTYPE(fdisk_table_get_partition);
extern DLSYM_PROTOTYPE(fdisk_unref_context);
extern DLSYM_PROTOTYPE(fdisk_unref_partition);
extern DLSYM_PROTOTYPE(fdisk_unref_parttype);
extern DLSYM_PROTOTYPE(fdisk_unref_table);
extern DLSYM_PROTOTYPE(fdisk_write_disklabel);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct fdisk_context*, sym_fdisk_unref_context, fdisk_unref_contextp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct fdisk_partition*, sym_fdisk_unref_partition, fdisk_unref_partitionp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct fdisk_parttype*, sym_fdisk_unref_parttype, fdisk_unref_parttypep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct fdisk_table*, sym_fdisk_unref_table, fdisk_unref_tablep, NULL);

int fdisk_new_context_at(int dir_fd, const char *path, bool read_only, uint32_t sector_size, struct fdisk_context **ret);

int fdisk_partition_get_uuid_as_id128(struct fdisk_partition *p, sd_id128_t *ret);
int fdisk_partition_get_type_as_id128(struct fdisk_partition *p, sd_id128_t *ret);

int fdisk_partition_get_attrs_as_uint64(struct fdisk_partition *pa, uint64_t *ret);
int fdisk_partition_set_attrs_as_uint64(struct fdisk_partition *pa, uint64_t flags);

#endif

int dlopen_fdisk(int log_level);
