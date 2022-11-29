/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fdisk-util.h"

#if HAVE_LIBFDISK

int fdisk_new_context_fd(int fd, bool read_only, struct fdisk_context **ret) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        int r;

        assert(ret);

        if (fd < 0)
                return -EBADF;

        c = fdisk_new_context();
        if (!c)
                return -ENOMEM;

        r = fdisk_assign_device(c, FORMAT_PROC_FD_PATH(fd), read_only);
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

#endif
