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

#include <stdio.h>

#include "alloc-util.h"
#include "log.h"
#include "string-util.h"
#include "khash.h"

int main(int argc, char *argv[]) {
        _cleanup_(khash_unrefp) khash *h = NULL, *copy = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        log_set_max_level(LOG_DEBUG);

        assert_se(khash_new(&h, NULL) == -EINVAL);
        assert_se(khash_new(&h, "") == -EINVAL);
        r = khash_new(&h, "foobar");
        if (r == -EAFNOSUPPORT) {
                puts("khash not supported on this kernel, skipping");
                return EXIT_TEST_SKIP;
        }
        assert_se(r == -EOPNOTSUPP);

        assert_se(khash_new(&h, "sha256") >= 0);
        assert_se(khash_get_size(h) == 32);
        assert_se(streq(khash_get_algorithm(h), "sha256"));

        assert_se(khash_digest_string(h, &s) >= 0);
        assert_se(streq(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        s = mfree(s);

        assert_se(khash_put(h, "foobar", 6) >= 0);
        assert_se(khash_digest_string(h, &s) >= 0);
        assert_se(streq(s, "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"));
        s = mfree(s);

        assert_se(khash_put(h, "piep", 4) >= 0);
        assert_se(khash_digest_string(h, &s) >= 0);
        assert_se(streq(s, "f114d872b5ea075d3be9040d0b7a429514b3f9324a8e8e3dc3fb24c34ee56bea"));
        s = mfree(s);

        assert_se(khash_put(h, "foo", 3) >= 0);
        assert_se(khash_dup(h, &copy) >= 0);

        assert_se(khash_put(h, "bar", 3) >= 0);
        assert_se(khash_put(copy, "bar", 3) >= 0);

        assert_se(khash_digest_string(h, &s) >= 0);
        assert_se(streq(s, "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"));
        s = mfree(s);

        assert_se(khash_digest_string(copy, &s) >= 0);
        assert_se(streq(s, "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"));
        s = mfree(s);

        h = khash_unref(h);

        assert_se(khash_new_with_key(&h, "hmac(sha256)", "quux", 4) >= 0);
        assert_se(khash_get_size(h) == 32);
        assert_se(streq(khash_get_algorithm(h), "hmac(sha256)"));

        assert_se(khash_digest_string(h, &s) >= 0);
        assert_se(streq(s, "abed9f8218ab473f77218a6a7d39abf1d21fa46d0700c4898e330ba88309d5ae"));
        s = mfree(s);

        assert_se(khash_put(h, "foobar", 6) >= 0);
        assert_se(khash_digest_string(h, &s) >= 0);
        assert_se(streq(s, "33f6c70a60db66007d5325d5d1dea37c371354e5b83347a59ad339ce9f4ba3dc"));

        return 0;
}
