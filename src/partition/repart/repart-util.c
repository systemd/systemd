/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "repart-util.h"
#

uint64_t round_down_size(uint64_t v, uint64_t p) {
        return (v / p) * p;
}

uint64_t round_up_size(uint64_t v, uint64_t p) {

        v = DIV_ROUND_UP(v, p);

        if (v > UINT64_MAX / p)
                return UINT64_MAX; /* overflow */

        return v * p;
}



