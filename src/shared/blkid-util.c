/* SPDX-License-Identifier: LGPL-2.1-or-later */
#if HAVE_BLKID

#include "sd-id128.h"

#include "blkid-util.h"
#include "string-util.h"

int blkid_partition_get_uuid_id128(blkid_partition p, sd_id128_t *ret) {
        const char *s;

        assert(p);

        s = blkid_partition_get_uuid(p);
        if (isempty(s))
                return -ENXIO;

        return sd_id128_from_string(s, ret);
}

int blkid_partition_get_type_id128(blkid_partition p, sd_id128_t *ret) {
        const char *s;

        assert(p);

        s = blkid_partition_get_type_string(p);
        if (isempty(s))
                return -ENXIO;

        return sd_id128_from_string(s, ret);
}

#endif
