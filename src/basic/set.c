/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering
***/

#include "alloc-util.h"
#include "set.h"

int set_make(Set **ret, const struct hash_ops *hash_ops HASHMAP_DEBUG_PARAMS, void *add, ...) {
        _cleanup_set_free_ Set *s = NULL;
        int r;

        assert(ret);

        s = set_new(hash_ops HASHMAP_DEBUG_PASS_ARGS);
        if (!s)
                return -ENOMEM;

        if (add) {
                va_list ap;

                r = set_put(s, add);
                if (r < 0)
                        return r;

                va_start(ap, add);

                for (;;) {
                        void *arg = va_arg(ap, void*);

                        if (!arg)
                                break;

                        r = set_put(s, arg);
                        if (r < 0) {
                                va_end(ap);
                                return r;
                        }
                }

                va_end(ap);
        }

        *ret = TAKE_PTR(s);

        return 0;
}
