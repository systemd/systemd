/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <sys/mount.h>

#include "alloc-util.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "mount-util.h"
#include "string-util.h"

static void test_mount_propagation_flags(const char *name, int ret, unsigned long expected) {
        long unsigned flags;

        assert_se(mount_propagation_flags_from_string(name, &flags) == ret);

        if (ret >= 0) {
                const char *c;

                assert_se(flags == expected);

                c = mount_propagation_flags_to_string(flags);
                if (isempty(name))
                        assert_se(isempty(c));
                else
                        assert_se(streq(c, name));
        }
}

static void test_mnt_id(void) {
        _cleanup_fclose_ FILE *f = NULL;
        Hashmap *h;
        Iterator i;
        char *k;
        void *p;
        int r;

        assert_se(f = fopen("/proc/self/mountinfo", "re"));
        assert_se(h = hashmap_new(&string_hash_ops));

        for (;;) {
                _cleanup_free_ char *line = NULL, *path = NULL;
                void *old_key;
                int mnt_id;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r == 0)
                        break;
                assert_se(r > 0);

                assert_se(sscanf(line, "%i %*s %*s %*s %ms", &mnt_id, &path) == 2);

                /* Add all mount points and their ids to a hashtable, so that we filter out mount points that are
                 * overmounted. For those we only care for the "upper" mount, since that's the only one
                 * path_get_mnt_id() can determine. */

                if (hashmap_remove2(h, path, &old_key))
                        free(old_key);

                assert_se(hashmap_put(h, path, INT_TO_PTR(mnt_id)) >= 0);
                path = NULL;
        }

        HASHMAP_FOREACH_KEY(p, k, h, i) {
                int mnt_id = PTR_TO_INT(p), mnt_id2;

                r = path_get_mnt_id(k, &mnt_id2);
                if (r == -EOPNOTSUPP) { /* kernel or file system too old? */
                        log_debug("%s doesn't support mount IDs\n", k);
                        continue;
                }
                if (IN_SET(r, -EACCES, -EPERM)) {
                        log_debug("Can't access %s\n", k);
                        continue;
                }

                log_debug("mnt id of %s is %i\n", k, mnt_id2);

                assert_se(r >= 0);
                assert_se(mnt_id == mnt_id2);
        }

        while ((k = hashmap_steal_first_key(h)))
                free(k);

        hashmap_free(h);
}

int main(int argc, char *argv[]) {

        log_set_max_level(LOG_DEBUG);

        test_mount_propagation_flags("shared", 0, MS_SHARED);
        test_mount_propagation_flags("slave", 0, MS_SLAVE);
        test_mount_propagation_flags("private", 0, MS_PRIVATE);
        test_mount_propagation_flags(NULL, 0, 0);
        test_mount_propagation_flags("", 0, 0);
        test_mount_propagation_flags("xxxx", -EINVAL, 0);
        test_mount_propagation_flags(" ", -EINVAL, 0);

        test_mnt_id();

        return 0;
}
