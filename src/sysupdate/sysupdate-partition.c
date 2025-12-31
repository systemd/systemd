/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>

#include "alloc-util.h"
#include "fdisk-util.h"
#include "gpt.h"
#include "log.h"
#include "string-util.h"
#include "sysupdate-partition.h"

void partition_info_destroy(PartitionInfo *p) {
        assert(p);

        p->label = mfree(p->label);
        p->device = mfree(p->device);
}

int partition_info_copy(PartitionInfo *dest, const PartitionInfo *src) {
        int r;

        assert(dest);
        assert(src);

        r = free_and_strdup_warn(&dest->label, src->label);
        if (r < 0)
                return r;

        r = free_and_strdup_warn(&dest->device, src->device);
        if (r < 0)
                return r;

        dest->partno = src->partno;
        dest->start = src->start;
        dest->size = src->size;
        dest->flags = src->flags;
        dest->type = src->type;
        dest->uuid = src->uuid;
        dest->no_auto = src->no_auto;
        dest->read_only = src->read_only;
        dest->growfs = src->growfs;

        return 0;
}

int read_partition_info(
                struct fdisk_context *c,
                struct fdisk_table *t,
                size_t i,
                PartitionInfo *ret) {

        _cleanup_free_ char *label_copy = NULL, *device = NULL;
        const char *label;
        struct fdisk_partition *p;
        uint64_t start, size, flags;
        unsigned long ssz;
        sd_id128_t ptid, id;
        GptPartitionType type;
        size_t partno;
        int r;

        assert(c);
        assert(t);
        assert(ret);

        p = fdisk_table_get_partition(t, i);
        if (!p)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read partition metadata.");

        if (fdisk_partition_is_used(p) <= 0) {
                *ret = (PartitionInfo) PARTITION_INFO_NULL;
                return 0; /* not found! */
        }

        if (fdisk_partition_has_partno(p) <= 0 ||
            fdisk_partition_has_start(p) <= 0 ||
            fdisk_partition_has_size(p) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Found a partition without a number, position or size.");

        partno = fdisk_partition_get_partno(p);

        start = fdisk_partition_get_start(p);
        ssz = fdisk_get_sector_size(c);
        assert(start <= UINT64_MAX / ssz);
        start *= ssz;

        size = fdisk_partition_get_size(p);
        assert(size <= UINT64_MAX / ssz);
        size *= ssz;

        label = fdisk_partition_get_name(p);
        if (!label)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Found a partition without a label.");

        r = fdisk_partition_get_type_as_id128(p, &ptid);
        if (r < 0)
                return log_error_errno(r, "Failed to read partition type UUID: %m");

        r = fdisk_partition_get_uuid_as_id128(p, &id);
        if (r < 0)
                return log_error_errno(r, "Failed to read partition UUID: %m");

        r = fdisk_partition_get_attrs_as_uint64(p, &flags);
        if (r < 0)
                return log_error_errno(r, "Failed to get partition flags: %m");

        r = fdisk_partition_to_string(p, c, FDISK_FIELD_DEVICE, &device);
        if (r != 0)
                return log_error_errno(r, "Failed to get partition device name: %m");

        label_copy = strdup(label);
        if (!label_copy)
                return log_oom();

        type = gpt_partition_type_from_uuid(ptid);

        *ret = (PartitionInfo) {
                .partno = partno,
                .start = start,
                .size = size,
                .flags = flags,
                .type = ptid,
                .uuid = id,
                .label = TAKE_PTR(label_copy),
                .device = TAKE_PTR(device),
                .no_auto = FLAGS_SET(flags, SD_GPT_FLAG_NO_AUTO) && gpt_partition_type_knows_no_auto(type),
                .read_only = FLAGS_SET(flags, SD_GPT_FLAG_READ_ONLY) && gpt_partition_type_knows_read_only(type),
                .growfs = FLAGS_SET(flags, SD_GPT_FLAG_GROWFS) && gpt_partition_type_knows_growfs(type),
        };

        return 1; /* found! */
}

int find_suitable_partition(
                const char *device,
                uint64_t space,
                sd_id128_t *partition_type,
                PartitionInfo *ret) {

        _cleanup_(partition_info_destroy) PartitionInfo smallest = PARTITION_INFO_NULL;
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        size_t n_partitions;
        int r;

        assert(device);
        assert(ret);

        r = fdisk_new_context_at(AT_FDCWD, device, /* read_only= */ true, /* sector_size= */ UINT32_MAX, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to create fdisk context from '%s': %m", device);

        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not suitable.", device);

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                _cleanup_(partition_info_destroy) PartitionInfo pinfo = PARTITION_INFO_NULL;

                r = read_partition_info(c, t, i, &pinfo);
                if (r < 0)
                        return r;
                if (r == 0) /* not assigned */
                        continue;

                /* Filter out non-matching partition types */
                if (partition_type && !sd_id128_equal(pinfo.type, *partition_type))
                        continue;

                if (!streq_ptr(pinfo.label, "_empty")) /* used */
                        continue;

                if (space != UINT64_MAX && pinfo.size < space) /* too small */
                        continue;

                if (smallest.partno != SIZE_MAX && smallest.size <= pinfo.size) /* already found smaller */
                        continue;

                smallest = pinfo;
                pinfo = (PartitionInfo) PARTITION_INFO_NULL;
        }

        if (smallest.partno == SIZE_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC), "No available partition of a suitable size found.");

        *ret = smallest;
        smallest = (PartitionInfo) PARTITION_INFO_NULL;

        return 0;
}

int patch_partition(
                const char *device,
                const PartitionInfo *info,
                PartitionChange change) {

        _cleanup_(fdisk_unref_partitionp) struct fdisk_partition *pa = NULL;
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        bool tweak_no_auto, tweak_read_only, tweak_growfs;
        GptPartitionType type;
        int r, fd;

        assert(device);
        assert(info);
        assert(change <= _PARTITION_CHANGE_MAX);

        if (change == 0) /* Nothing to do */
                return 0;

        r = fdisk_new_context_at(AT_FDCWD, device, /* read_only= */ false, /* sector_size= */ UINT32_MAX, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to create fdisk context from '%s': %m", device);

        assert_se((fd = fdisk_get_devfd(c)) >= 0);

        /* Make sure udev doesn't read the device while we make changes (this lock is released automatically
         * by the kernel when the fd is closed, i.e. when the fdisk context is freed, hence no explicit
         * unlock by us here anywhere.) */
        if (flock(fd, LOCK_EX) < 0)
                return log_error_errno(errno, "Failed to lock block device '%s': %m", device);

        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not suitable.", device);

        r = fdisk_get_partition(c, info->partno, &pa);
        if (r < 0)
                return log_error_errno(r, "Failed to read partition %zu of GPT label of '%s': %m", info->partno, device);

        if (change & PARTITION_LABEL) {
                r = fdisk_partition_set_name(pa, info->label);
                if (r < 0)
                        return log_error_errno(r, "Failed to update partition label: %m");
        }

        if (change & PARTITION_UUID) {
                r = fdisk_partition_set_uuid(pa, SD_ID128_TO_UUID_STRING(info->uuid));
                if (r < 0)
                        return log_error_errno(r, "Failed to update partition UUID: %m");
        }

        type = gpt_partition_type_from_uuid(info->type);

        /* Tweak the read-only flag, but only if supported by the partition type */
        tweak_no_auto =
                FLAGS_SET(change, PARTITION_NO_AUTO) &&
                gpt_partition_type_knows_no_auto(type);
        tweak_read_only =
                FLAGS_SET(change, PARTITION_READ_ONLY) &&
                gpt_partition_type_knows_read_only(type);
        tweak_growfs =
                FLAGS_SET(change, PARTITION_GROWFS) &&
                gpt_partition_type_knows_growfs(type);

        if (change & PARTITION_FLAGS) {
                uint64_t flags;

                /* Update the full flags parameter, and import the read-only flag into it */

                flags = info->flags;
                if (tweak_no_auto)
                        SET_FLAG(flags, SD_GPT_FLAG_NO_AUTO, info->no_auto);
                if (tweak_read_only)
                        SET_FLAG(flags, SD_GPT_FLAG_READ_ONLY, info->read_only);
                if (tweak_growfs)
                        SET_FLAG(flags, SD_GPT_FLAG_GROWFS, info->growfs);

                r = fdisk_partition_set_attrs_as_uint64(pa, flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to update partition flags: %m");

        } else if (tweak_no_auto || tweak_read_only || tweak_growfs) {
                uint64_t old_flags, new_flags;

                /* So we aren't supposed to update the full flags parameter, but we are supposed to update
                 * the RO flag of it. */

                r = fdisk_partition_get_attrs_as_uint64(pa, &old_flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to get old partition flags: %m");

                new_flags = old_flags;
                if (tweak_no_auto)
                        SET_FLAG(new_flags, SD_GPT_FLAG_NO_AUTO, info->no_auto);
                if (tweak_read_only)
                        SET_FLAG(new_flags, SD_GPT_FLAG_READ_ONLY, info->read_only);
                if (tweak_growfs)
                        SET_FLAG(new_flags, SD_GPT_FLAG_GROWFS, info->growfs);

                if (new_flags != old_flags) {
                        r = fdisk_partition_set_attrs_as_uint64(pa, new_flags);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update partition flags: %m");
                }
        }

        r = fdisk_set_partition(c, info->partno, pa);
        if (r < 0)
                return log_error_errno(r, "Failed to update partition: %m");

        r = fdisk_write_disklabel(c);
        if (r < 0)
                return log_error_errno(r, "Failed to write updated partition table: %m");

        return 0;
}
