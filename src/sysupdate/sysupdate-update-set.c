/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ansi-color.h"
#include "alloc-util.h"
#include "string-util.h"
#include "sysupdate-update-set.h"

UpdateSet* update_set_free(UpdateSet *us) {
        if (!us)
                return NULL;

        free(us->version);
        free(us->instances); /* The objects referenced by this array are freed via resource_free(), not us */

        return mfree(us);
}

int update_set_cmp(UpdateSet *const*a, UpdateSet *const*b) {
        assert(a);
        assert(b);
        assert(*a);
        assert(*b);
        assert((*a)->version);
        assert((*b)->version);

        /* Newest version at the beginning */
        return -strverscmp_improved((*a)->version, (*b)->version);
}
