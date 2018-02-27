/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <stdbool.h>

#include "journald-server.h"

#define _COMPRESS_PARSE_CHECK(str, enab, thresh, varname)               \
        do {                                                            \
                JournalCompressOptions varname = {true, 111};           \
                config_parse_compress("", "", 0, "", 0, "", 0, str,     \
                                      &varname, NULL);                  \
                assert_se((enab) == varname.enabled);                   \
                if (varname.enabled)                                    \
                        assert_se((thresh) == varname.threshold_bytes); \
        } while (0)

#define COMPRESS_PARSE_CHECK(str, enabled, threshold)                   \
        _COMPRESS_PARSE_CHECK(str, enabled, threshold, conf##__COUNTER__)

static void test_config_compress(void) {
        COMPRESS_PARSE_CHECK("yes", true, 111);
        COMPRESS_PARSE_CHECK("no", false, 111);
        COMPRESS_PARSE_CHECK("y", true, 111);
        COMPRESS_PARSE_CHECK("n", false, 111);
        COMPRESS_PARSE_CHECK("true", true, 111);
        COMPRESS_PARSE_CHECK("false", false, 111);
        COMPRESS_PARSE_CHECK("t", true, 111);
        COMPRESS_PARSE_CHECK("f", false, 111);
        COMPRESS_PARSE_CHECK("on", true, 111);
        COMPRESS_PARSE_CHECK("off", false, 111);

        /* Weird size/bool overlapping case. We preserve backward compatibility instead of assuming these are byte
         * counts. */
        COMPRESS_PARSE_CHECK("1", true, 111);
        COMPRESS_PARSE_CHECK("0", false, 111);

        /* IEC sizing */
        COMPRESS_PARSE_CHECK("1B", true, 1);
        COMPRESS_PARSE_CHECK("1K", true, 1024);
        COMPRESS_PARSE_CHECK("1M", true, 1024 * 1024);
        COMPRESS_PARSE_CHECK("1G", true, 1024 * 1024 * 1024);

        /* Invalid Case */
        COMPRESS_PARSE_CHECK("-1", true, 111);
        COMPRESS_PARSE_CHECK("blah blah", true, 111);
        COMPRESS_PARSE_CHECK("", true, (uint64_t)-1);
}

int main(int argc, char *argv[]) {
        test_config_compress();

        return 0;
}
