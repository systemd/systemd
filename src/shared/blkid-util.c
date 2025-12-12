/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/syslog.h>

#include "sd-id128.h"

#include "blkid-util.h"
#include "parse-util.h"
#include "string-util.h"

#if HAVE_BLKID
static void *libblkid_dl = NULL;

DLSYM_PROTOTYPE(blkid_do_fullprobe) = NULL;
DLSYM_PROTOTYPE(blkid_do_probe) = NULL;
DLSYM_PROTOTYPE(blkid_do_safeprobe) = NULL;
DLSYM_PROTOTYPE(blkid_do_wipe) = NULL;
DLSYM_PROTOTYPE(blkid_encode_string) = NULL;
DLSYM_PROTOTYPE(blkid_free_probe) = NULL;
DLSYM_PROTOTYPE(blkid_new_probe) = NULL;
DLSYM_PROTOTYPE(blkid_new_probe_from_filename) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_flags) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_name) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_partno) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_size) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_start) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_type) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_type_string) = NULL;
DLSYM_PROTOTYPE(blkid_partition_get_uuid) = NULL;
DLSYM_PROTOTYPE(blkid_partlist_devno_to_partition) = NULL;
DLSYM_PROTOTYPE(blkid_partlist_get_partition) = NULL;
DLSYM_PROTOTYPE(blkid_partlist_numof_partitions) = NULL;
DLSYM_PROTOTYPE(blkid_probe_enable_partitions) = NULL;
DLSYM_PROTOTYPE(blkid_probe_enable_superblocks) = NULL;
DLSYM_PROTOTYPE(blkid_probe_filter_superblocks_type) = NULL;
DLSYM_PROTOTYPE(blkid_probe_filter_superblocks_usage) = NULL;
DLSYM_PROTOTYPE(blkid_probe_get_fd) = NULL;
DLSYM_PROTOTYPE(blkid_probe_get_partitions) = NULL;
DLSYM_PROTOTYPE(blkid_probe_get_size) = NULL;
DLSYM_PROTOTYPE(blkid_probe_get_value) = NULL;
DLSYM_PROTOTYPE(blkid_probe_is_wholedisk) = NULL;
DLSYM_PROTOTYPE(blkid_probe_lookup_value) = NULL;
DLSYM_PROTOTYPE(blkid_probe_numof_values) = NULL;
DLSYM_PROTOTYPE(blkid_probe_set_device) = NULL;
DLSYM_PROTOTYPE(blkid_probe_set_hint) = NULL;
DLSYM_PROTOTYPE(blkid_probe_set_partitions_flags) = NULL;
DLSYM_PROTOTYPE(blkid_probe_set_sectorsize) = NULL;
DLSYM_PROTOTYPE(blkid_probe_set_superblocks_flags) = NULL;
DLSYM_PROTOTYPE(blkid_safe_string) = NULL;

int dlopen_libblkid(void) {
        ELF_NOTE_DLOPEN("blkid",
                        "Support for block device identification",
                        ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
                        "libblkid.so.1");

        return dlopen_many_sym_or_warn(
                        &libblkid_dl,
                        "libblkid.so.1",
                        LOG_DEBUG,
                        DLSYM_ARG(blkid_do_fullprobe),
                        DLSYM_ARG(blkid_do_probe),
                        DLSYM_ARG(blkid_do_safeprobe),
                        DLSYM_ARG(blkid_do_wipe),
                        DLSYM_ARG(blkid_encode_string),
                        DLSYM_ARG(blkid_free_probe),
                        DLSYM_ARG(blkid_new_probe),
                        DLSYM_ARG(blkid_new_probe_from_filename),
                        DLSYM_ARG(blkid_partition_get_flags),
                        DLSYM_ARG(blkid_partition_get_name),
                        DLSYM_ARG(blkid_partition_get_partno),
                        DLSYM_ARG(blkid_partition_get_size),
                        DLSYM_ARG(blkid_partition_get_start),
                        DLSYM_ARG(blkid_partition_get_type),
                        DLSYM_ARG(blkid_partition_get_type_string),
                        DLSYM_ARG(blkid_partition_get_uuid),
                        DLSYM_ARG(blkid_partlist_devno_to_partition),
                        DLSYM_ARG(blkid_partlist_get_partition),
                        DLSYM_ARG(blkid_partlist_numof_partitions),
                        DLSYM_ARG(blkid_probe_enable_partitions),
                        DLSYM_ARG(blkid_probe_enable_superblocks),
                        DLSYM_ARG(blkid_probe_filter_superblocks_type),
                        DLSYM_ARG(blkid_probe_filter_superblocks_usage),
                        DLSYM_ARG(blkid_probe_get_fd),
                        DLSYM_ARG(blkid_probe_get_partitions),
                        DLSYM_ARG(blkid_probe_get_size),
                        DLSYM_ARG(blkid_probe_get_value),
                        DLSYM_ARG(blkid_probe_is_wholedisk),
                        DLSYM_ARG(blkid_probe_lookup_value),
                        DLSYM_ARG(blkid_probe_numof_values),
                        DLSYM_ARG(blkid_probe_set_device),
                        DLSYM_ARG(blkid_probe_set_hint),
                        DLSYM_ARG(blkid_probe_set_partitions_flags),
                        DLSYM_ARG(blkid_probe_set_sectorsize),
                        DLSYM_ARG(blkid_probe_set_superblocks_flags),
                        DLSYM_ARG(blkid_safe_string));
}

int blkid_partition_get_uuid_id128(blkid_partition p, sd_id128_t *ret) {
        const char *s;

        assert(p);

        s = sym_blkid_partition_get_uuid(p);
        if (isempty(s))
                return -ENXIO;

        return sd_id128_from_string(s, ret);
}

int blkid_partition_get_type_id128(blkid_partition p, sd_id128_t *ret) {
        const char *s;

        assert(p);

        s = sym_blkid_partition_get_type_string(p);
        if (isempty(s))
                return -ENXIO;

        return sd_id128_from_string(s, ret);
}

int blkid_probe_lookup_value_id128(blkid_probe b, const char *field, sd_id128_t *ret) {
        assert(b);
        assert(field);

        const char *u = NULL;
        (void) sym_blkid_probe_lookup_value(b, field, &u, /* ret_size= */ NULL);
        if (!u)
                return -ENXIO;

        return sd_id128_from_string(u, ret);
}

int blkid_probe_lookup_value_u64(blkid_probe b, const char *field, uint64_t *ret) {
        assert(b);
        assert(field);

        const char *u = NULL;
        (void) sym_blkid_probe_lookup_value(b, field, &u, /* ret_size= */ NULL);
        if (!u)
                return -ENXIO;

        return safe_atou64(u, ret);
}
#endif
