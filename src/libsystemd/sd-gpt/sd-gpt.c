/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"
#include "gpt.h"

_public_ int sd_gpt_uuid_from_name(const char *name, sd_id128_t *ret) {
        GptPartitionType type;
        int r;

        assert_return(name, -EINVAL);

        r = gpt_partition_type_from_string(name, &type);
        if (r < 0)
                return r;

        if (ret)
                *ret = type.uuid;
        return 0;
}
