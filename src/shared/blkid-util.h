/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_BLKID

#include <blkid.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(blkid_do_fullprobe);
extern DLSYM_PROTOTYPE(blkid_do_probe);
extern DLSYM_PROTOTYPE(blkid_do_safeprobe);
extern DLSYM_PROTOTYPE(blkid_do_wipe);
extern DLSYM_PROTOTYPE(blkid_encode_string);
extern DLSYM_PROTOTYPE(blkid_free_probe);
extern DLSYM_PROTOTYPE(blkid_new_probe);
extern DLSYM_PROTOTYPE(blkid_new_probe_from_filename);
extern DLSYM_PROTOTYPE(blkid_partition_get_flags);
extern DLSYM_PROTOTYPE(blkid_partition_get_name);
extern DLSYM_PROTOTYPE(blkid_partition_get_partno);
extern DLSYM_PROTOTYPE(blkid_partition_get_size);
extern DLSYM_PROTOTYPE(blkid_partition_get_start);
extern DLSYM_PROTOTYPE(blkid_partition_get_type);
extern DLSYM_PROTOTYPE(blkid_partition_get_type_string);
extern DLSYM_PROTOTYPE(blkid_partition_get_uuid);
extern DLSYM_PROTOTYPE(blkid_partlist_devno_to_partition);
extern DLSYM_PROTOTYPE(blkid_partlist_get_partition);
extern DLSYM_PROTOTYPE(blkid_partlist_numof_partitions);
extern DLSYM_PROTOTYPE(blkid_probe_enable_partitions);
extern DLSYM_PROTOTYPE(blkid_probe_enable_superblocks);
extern DLSYM_PROTOTYPE(blkid_probe_filter_superblocks_type);
extern DLSYM_PROTOTYPE(blkid_probe_filter_superblocks_usage);
extern DLSYM_PROTOTYPE(blkid_probe_get_fd);
extern DLSYM_PROTOTYPE(blkid_probe_get_partitions);
extern DLSYM_PROTOTYPE(blkid_probe_get_size);
extern DLSYM_PROTOTYPE(blkid_probe_get_value);
extern DLSYM_PROTOTYPE(blkid_probe_is_wholedisk);
extern DLSYM_PROTOTYPE(blkid_probe_lookup_value);
extern DLSYM_PROTOTYPE(blkid_probe_numof_values);
extern DLSYM_PROTOTYPE(blkid_probe_set_device);
extern DLSYM_PROTOTYPE(blkid_probe_set_hint);
extern DLSYM_PROTOTYPE(blkid_probe_set_partitions_flags);
extern DLSYM_PROTOTYPE(blkid_probe_set_sectorsize);
extern DLSYM_PROTOTYPE(blkid_probe_set_superblocks_flags);
extern DLSYM_PROTOTYPE(blkid_safe_string);

int dlopen_libblkid(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(blkid_probe, sym_blkid_free_probe, blkid_free_probep, NULL);

int blkid_partition_get_uuid_id128(blkid_partition p, sd_id128_t *ret);

int blkid_partition_get_type_id128(blkid_partition p, sd_id128_t *ret);

/* Define symbolic names for blkid_do_safeprobe() return values, since blkid only uses literal numbers. We
 * prefix these symbolic definitions with underscores, to not invade libblkid's namespace needlessly. */
enum {
        _BLKID_SAFEPROBE_FOUND     =  0,
        _BLKID_SAFEPROBE_NOT_FOUND =  1,
        _BLKID_SAFEPROBE_AMBIGUOUS = -2,
        _BLKID_SAFEPROBE_ERROR     = -1,
};

int blkid_probe_lookup_value_id128(blkid_probe b, const char *field, sd_id128_t *ret);
int blkid_probe_lookup_value_u64(blkid_probe b, const char *field, uint64_t *ret);
#else
static inline int dlopen_libblkid(void) {
        return -EOPNOTSUPP;
}
#endif
