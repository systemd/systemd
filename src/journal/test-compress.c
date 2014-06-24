/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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

#include "compress.h"
#include "util.h"
#include "macro.h"

static void test_compress_uncompress(void) {
        char text[] = "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF"
                      "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF";
        char compressed[512];
        uint64_t csize = 512;
        uint64_t usize = 0;
        _cleanup_free_ char *uncompressed = NULL;

        assert_se(compress_blob(text, sizeof(text), compressed, &csize));
        assert_se(uncompress_blob(compressed,
                                  csize,
                                  (void **) &uncompressed,
                                  &usize, &csize, 0));
        assert_se(uncompressed);
        assert_se(streq(uncompressed, text));
        assert_se(!uncompress_blob("garbage",
                                   7,
                                   (void **) &uncompressed,
                                   &usize, &csize, 0));
}

static void test_uncompress_startswith(void) {
        char text[] = "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF"
                      "foofoofoofoo AAAA aaaaaaaaa ghost busters barbarbar FFF";
        char compressed[512];
        uint64_t csize = 512;
        uint64_t usize = 0;
        _cleanup_free_ char *uncompressed = NULL;

        assert_se(compress_blob(text, sizeof(text), compressed, &csize));
        assert_se(uncompress_startswith(compressed,
                                        csize,
                                        (void **) &uncompressed,
                                        &usize,
                                        "foofoofoofoo", 12, ' '));
        assert_se(!uncompress_startswith(compressed,
                                         csize,
                                        (void **) &uncompressed,
                                        &usize,
                                        "foofoofoofoo", 12, 'w'));
        assert_se(!uncompress_startswith(compressed,
                                         csize,
                                        (void **) &uncompressed,
                                        &usize,
                                        "barbarbar", 9, ' '));
}

int main(int argc, char *argv[]) {
        test_compress_uncompress();
        test_uncompress_startswith();

        return 0;
}
