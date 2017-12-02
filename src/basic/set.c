/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

        *ret = s;
        s = NULL;

        return 0;
}
