/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "static-destruct.h"

void static_destruct_impl(const StaticDestructor *start, const StaticDestructor *end) {
        if (!start)
                return;

        for (const StaticDestructor *d = start; d < end; d++)
                switch (d->type) {
                case STATIC_DESTRUCTOR_SIMPLE:
                        d->simple.destroy(d->simple.data);
                        break;

                case STATIC_DESTRUCTOR_ARRAY:
                        array_cleanup(&d->array);
                        break;

                default:
                        assert_not_reached();
                }
}
