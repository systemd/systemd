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

#include "alloc-util.h"
#include "log.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"

static void test_specifier_escape_one(const char *a, const char *b) {
        _cleanup_free_ char *x = NULL;

        x = specifier_escape(a);
        assert_se(streq_ptr(x, b));
}

static void test_specifier_escape(void) {
        test_specifier_escape_one(NULL, NULL);
        test_specifier_escape_one("", "");
        test_specifier_escape_one("%", "%%");
        test_specifier_escape_one("foo bar", "foo bar");
        test_specifier_escape_one("foo%bar", "foo%%bar");
        test_specifier_escape_one("%%%%%", "%%%%%%%%%%");
}

static void test_specifier_escape_strv_one(char **a, char **b) {
        _cleanup_strv_free_ char **x = NULL;

        assert_se(specifier_escape_strv(a, &x) >= 0);
        assert_se(strv_equal(x, b));
}

static void test_specifier_escape_strv(void) {
        test_specifier_escape_strv_one(NULL, NULL);
        test_specifier_escape_strv_one(STRV_MAKE(NULL), STRV_MAKE(NULL));
        test_specifier_escape_strv_one(STRV_MAKE(""), STRV_MAKE(""));
        test_specifier_escape_strv_one(STRV_MAKE("foo"), STRV_MAKE("foo"));
        test_specifier_escape_strv_one(STRV_MAKE("%"), STRV_MAKE("%%"));
        test_specifier_escape_strv_one(STRV_MAKE("foo", "%", "foo%", "%foo", "foo%foo", "quux", "%%%"), STRV_MAKE("foo", "%%", "foo%%", "%%foo", "foo%%foo", "quux", "%%%%%%"));
}

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);

        test_specifier_escape();
        test_specifier_escape_strv();

        return 0;
}
