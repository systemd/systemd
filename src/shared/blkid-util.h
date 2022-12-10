/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_BLKID
#  include <blkid.h>

#  include "sd-id128.h"

#  include "macro.h"
#  include "string-util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(blkid_probe, blkid_free_probe, NULL);

static inline int blkid_partition_get_uuid_id128(blkid_partition p, sd_id128_t *ret) {
        const char *s;

        assert(p);

        s = blkid_partition_get_uuid(p);
        if (isempty(s))
                return -ENXIO;

        return sd_id128_from_string(s, ret);
}

static inline int blkid_partition_get_type_id128(blkid_partition p, sd_id128_t *ret) {
        const char *s;

        assert(p);

        s = blkid_partition_get_type_string(p);
        if (isempty(s))
                return -ENXIO;

        return sd_id128_from_string(s, ret);
}

/* Define symbolic names for blkid_do_safeprobe() return values, since blkid only uses literal numbers. We
 * prefix these symbolic definitions with underscores, to not invade libblkid's namespace needlessly. */
enum {
        _BLKID_SAFEPROBE_FOUND     =  0,
        _BLKID_SAFEPROBE_NOT_FOUND =  1,
        _BLKID_SAFEPROBE_AMBIGUOUS = -2,
        _BLKID_SAFEPROBE_ERROR     = -1,
};

#endif
