/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitfield.h"
#include "dissect-image.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdisk-util.h"
#include "parse-util.h"

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

        c = fdisk_new_context();
        if (!c)
                return -ENOMEM;

        if (sector_size == UINT32_MAX) {
                r = probe_sector_size_prefer_ioctl(dir_fd, &sector_size);
                if (r < 0)
                        return r;
        }

        if (sector_size != 0) {
                r = fdisk_save_user_sector_size(c, /* phy= */ 0, sector_size);
                if (r < 0)
                        return r;
        }

        r = fdisk_assign_device(c, FORMAT_PROC_FD_PATH(dir_fd), read_only);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int fdisk_partition_get_uuid_as_id128(struct fdisk_partition *p, sd_id128_t *ret) {
        const char *ids;

        assert(p);
        assert(ret);

        ids = fdisk_partition_get_uuid(p);
        if (!ids)
                return -ENXIO;

        return sd_id128_from_string(ids, ret);
}

int fdisk_partition_get_type_as_id128(struct fdisk_partition *p, sd_id128_t *ret) {
        struct fdisk_parttype *pt;
        const char *pts;

        assert(p);
        assert(ret);

        pt = fdisk_partition_get_type(p);
        if (!pt)
                return -ENXIO;

        pts = fdisk_parttype_get_string(pt);
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

        a = fdisk_partition_get_attrs(pa);
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

        return fdisk_partition_set_attrs(pa, strempty(attrs));
}

#endif
