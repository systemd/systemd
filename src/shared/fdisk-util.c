/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fdisk-util.h"
#include "log.h"

#if HAVE_LIBFDISK

#include "sd-dlopen.h"

#include "alloc-util.h"
#include "bitfield.h"
#include "dissect-image.h"
#include "dlfcn-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "parse-util.h"
#include "string-util.h"

static void *fdisk_dl = NULL;

DLSYM_PROTOTYPE(fdisk_add_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_apply_table) = NULL;
DLSYM_PROTOTYPE(fdisk_ask_get_type) = NULL;
DLSYM_PROTOTYPE(fdisk_ask_string_set_result) = NULL;
DLSYM_PROTOTYPE(fdisk_assign_device) = NULL;
DLSYM_PROTOTYPE(fdisk_create_disklabel) = NULL;
DLSYM_PROTOTYPE(fdisk_delete_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_get_devfd) = NULL;
DLSYM_PROTOTYPE(fdisk_get_disklabel_id) = NULL;
DLSYM_PROTOTYPE(fdisk_get_first_lba) = NULL;
DLSYM_PROTOTYPE(fdisk_get_grain_size) = NULL;
DLSYM_PROTOTYPE(fdisk_get_last_lba) = NULL;
DLSYM_PROTOTYPE(fdisk_get_npartitions) = NULL;
DLSYM_PROTOTYPE(fdisk_get_nsectors) = NULL;
DLSYM_PROTOTYPE(fdisk_get_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_get_partitions) = NULL;
DLSYM_PROTOTYPE(fdisk_get_sector_size) = NULL;
DLSYM_PROTOTYPE(fdisk_has_label) = NULL;
DLSYM_PROTOTYPE(fdisk_is_labeltype) = NULL;
DLSYM_PROTOTYPE(fdisk_new_context) = NULL;
DLSYM_PROTOTYPE(fdisk_new_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_new_parttype) = NULL;
DLSYM_PROTOTYPE(fdisk_partname) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_attrs) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_end) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_name) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_partno) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_size) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_start) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_type) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_get_uuid) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_has_end) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_has_partno) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_has_size) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_has_start) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_is_used) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_partno_follow_default) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_attrs) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_name) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_partno) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_size) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_start) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_type) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_set_uuid) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_size_explicit) = NULL;
DLSYM_PROTOTYPE(fdisk_partition_to_string) = NULL;
DLSYM_PROTOTYPE(fdisk_parttype_get_string) = NULL;
DLSYM_PROTOTYPE(fdisk_parttype_set_typestr) = NULL;
DLSYM_PROTOTYPE(fdisk_ref_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_save_user_sector_size) = NULL;
DLSYM_PROTOTYPE(fdisk_set_ask) = NULL;
DLSYM_PROTOTYPE(fdisk_set_disklabel_id) = NULL;
DLSYM_PROTOTYPE(fdisk_set_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_table_get_nents) = NULL;
DLSYM_PROTOTYPE(fdisk_table_get_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_unref_context) = NULL;
DLSYM_PROTOTYPE(fdisk_unref_partition) = NULL;
DLSYM_PROTOTYPE(fdisk_unref_parttype) = NULL;
DLSYM_PROTOTYPE(fdisk_unref_table) = NULL;
DLSYM_PROTOTYPE(fdisk_write_disklabel) = NULL;
#endif

int dlopen_fdisk(int log_level) {
#if HAVE_LIBFDISK
        SD_ELF_NOTE_DLOPEN(
                        "fdisk",
                        "Support for reading and writing partition tables",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libfdisk.so.1");

        return dlopen_many_sym_or_warn(
                        &fdisk_dl,
                        "libfdisk.so.1",
                        log_level,
                        DLSYM_ARG(fdisk_add_partition),
                        DLSYM_ARG(fdisk_apply_table),
                        DLSYM_ARG(fdisk_ask_get_type),
                        DLSYM_ARG(fdisk_ask_string_set_result),
                        DLSYM_ARG(fdisk_assign_device),
                        DLSYM_ARG(fdisk_create_disklabel),
                        DLSYM_ARG(fdisk_delete_partition),
                        DLSYM_ARG(fdisk_get_devfd),
                        DLSYM_ARG(fdisk_get_disklabel_id),
                        DLSYM_ARG(fdisk_get_first_lba),
                        DLSYM_ARG(fdisk_get_grain_size),
                        DLSYM_ARG(fdisk_get_last_lba),
                        DLSYM_ARG(fdisk_get_npartitions),
                        DLSYM_ARG(fdisk_get_nsectors),
                        DLSYM_ARG(fdisk_get_partition),
                        DLSYM_ARG(fdisk_get_partitions),
                        DLSYM_ARG(fdisk_get_sector_size),
                        DLSYM_ARG(fdisk_has_label),
                        DLSYM_ARG(fdisk_is_labeltype),
                        DLSYM_ARG(fdisk_new_context),
                        DLSYM_ARG(fdisk_new_partition),
                        DLSYM_ARG(fdisk_new_parttype),
                        DLSYM_ARG(fdisk_partname),
                        DLSYM_ARG(fdisk_partition_get_attrs),
                        DLSYM_ARG(fdisk_partition_get_end),
                        DLSYM_ARG(fdisk_partition_get_name),
                        DLSYM_ARG(fdisk_partition_get_partno),
                        DLSYM_ARG(fdisk_partition_get_size),
                        DLSYM_ARG(fdisk_partition_get_start),
                        DLSYM_ARG(fdisk_partition_get_type),
                        DLSYM_ARG(fdisk_partition_get_uuid),
                        DLSYM_ARG(fdisk_partition_has_end),
                        DLSYM_ARG(fdisk_partition_has_partno),
                        DLSYM_ARG(fdisk_partition_has_size),
                        DLSYM_ARG(fdisk_partition_has_start),
                        DLSYM_ARG(fdisk_partition_is_used),
                        DLSYM_ARG(fdisk_partition_partno_follow_default),
                        DLSYM_ARG(fdisk_partition_set_attrs),
                        DLSYM_ARG(fdisk_partition_set_name),
                        DLSYM_ARG(fdisk_partition_set_partno),
                        DLSYM_ARG(fdisk_partition_set_size),
                        DLSYM_ARG(fdisk_partition_set_start),
                        DLSYM_ARG(fdisk_partition_set_type),
                        DLSYM_ARG(fdisk_partition_set_uuid),
                        DLSYM_ARG(fdisk_partition_size_explicit),
                        DLSYM_ARG(fdisk_partition_to_string),
                        DLSYM_ARG(fdisk_parttype_get_string),
                        DLSYM_ARG(fdisk_parttype_set_typestr),
                        DLSYM_ARG(fdisk_ref_partition),
                        DLSYM_ARG(fdisk_save_user_sector_size),
                        DLSYM_ARG(fdisk_set_ask),
                        DLSYM_ARG(fdisk_set_disklabel_id),
                        DLSYM_ARG(fdisk_set_partition),
                        DLSYM_ARG(fdisk_table_get_nents),
                        DLSYM_ARG(fdisk_table_get_partition),
                        DLSYM_ARG(fdisk_unref_context),
                        DLSYM_ARG(fdisk_unref_partition),
                        DLSYM_ARG(fdisk_unref_parttype),
                        DLSYM_ARG(fdisk_unref_table),
                        DLSYM_ARG(fdisk_write_disklabel));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libfdisk support is not compiled in.");
#endif
}

#if HAVE_LIBFDISK
int fdisk_new_context_at(
                int dir_fd,
                const char *path,
                bool read_only,
                uint32_t sector_size,
                struct fdisk_context **ret) {

        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        if (!isempty(path)) {
                fd = openat(dir_fd, path, (read_only ? O_RDONLY : O_RDWR)|O_CLOEXEC);
                if (fd < 0)
                        return -errno;

                dir_fd = fd;
        }

        c = sym_fdisk_new_context();
        if (!c)
                return -ENOMEM;

        if (sector_size == UINT32_MAX) {
                r = probe_sector_size_prefer_ioctl(dir_fd, &sector_size);
                if (r < 0)
                        return r;
        }

        if (sector_size != 0) {
                r = sym_fdisk_save_user_sector_size(c, /* phy= */ 0, sector_size);
                if (r < 0)
                        return r;
        }

        r = sym_fdisk_assign_device(c, FORMAT_PROC_FD_PATH(dir_fd), read_only);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int fdisk_partition_get_uuid_as_id128(struct fdisk_partition *p, sd_id128_t *ret) {
        const char *ids;

        assert(p);
        assert(ret);

        ids = sym_fdisk_partition_get_uuid(p);
        if (!ids)
                return -ENXIO;

        return sd_id128_from_string(ids, ret);
}

int fdisk_partition_get_type_as_id128(struct fdisk_partition *p, sd_id128_t *ret) {
        struct fdisk_parttype *pt;
        const char *pts;

        assert(p);
        assert(ret);

        pt = sym_fdisk_partition_get_type(p);
        if (!pt)
                return -ENXIO;

        pts = sym_fdisk_parttype_get_string(pt);
        if (!pts)
                return -ENXIO;

        return sd_id128_from_string(pts, ret);
}

int fdisk_partition_get_attrs_as_uint64(struct fdisk_partition *pa, uint64_t *ret) {
        uint64_t flags = 0;
        const char *a;
        int r;

        assert(pa);
        assert(ret);

        /* Retrieve current flags as uint64_t mask */

        a = sym_fdisk_partition_get_attrs(pa);
        if (!a) {
                *ret = 0;
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&a, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (streq(word, "RequiredPartition"))
                        flags |= SD_GPT_FLAG_REQUIRED_PARTITION;
                else if (streq(word, "NoBlockIOProtocol"))
                        flags |= SD_GPT_FLAG_NO_BLOCK_IO_PROTOCOL;
                else if (streq(word, "LegacyBIOSBootable"))
                        flags |= SD_GPT_FLAG_LEGACY_BIOS_BOOTABLE;
                else {
                        const char *e;
                        unsigned u;

                        /* Drop "GUID" prefix if specified */
                        e = startswith(word, "GUID:") ?: word;

                        if (safe_atou(e, &u) < 0) {
                                log_debug("Unknown partition flag '%s', ignoring.", word);
                                continue;
                        }

                        if (u >= sizeof(flags)*8) { /* partition flags on GPT are 64-bit. Let's ignore any further
                                                       bits should libfdisk report them */
                                log_debug("Partition flag above bit 63 (%s), ignoring.", word);
                                continue;
                        }

                        flags |= UINT64_C(1) << u;
                }
        }

        *ret = flags;
        return 0;
}

int fdisk_partition_set_attrs_as_uint64(struct fdisk_partition *pa, uint64_t flags) {
        _cleanup_free_ char *attrs = NULL;
        int r;

        assert(pa);

        for (unsigned i = 0; i < sizeof(flags) * 8; i++) {
                if (!BIT_SET(flags, i))
                        continue;

                r = strextendf_with_separator(&attrs, ",", "%u", i);
                if (r < 0)
                        return r;
        }

        return sym_fdisk_partition_set_attrs(pa, strempty(attrs));
}

#endif
