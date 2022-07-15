/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ioprio-util.h"
#include "parse-util.h"
#include "string-table.h"

int ioprio_parse_priority(const char *s, int *ret) {
        int i, r;

        assert(s);
        assert(ret);

        r = safe_atoi(s, &i);
        if (r < 0)
                return r;

        if (!ioprio_priority_is_valid(i))
                return -EINVAL;

        *ret = i;
        return 0;
}

static const char *const ioprio_class_table[] = {
        [IOPRIO_CLASS_NONE] = "none",
        [IOPRIO_CLASS_RT] = "realtime",
        [IOPRIO_CLASS_BE] = "best-effort",
        [IOPRIO_CLASS_IDLE] = "idle",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ioprio_class, int, IOPRIO_N_CLASSES);
