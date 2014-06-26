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

static void test_compress_stream(const char *srcfile) {
        _cleanup_close_ int src = -1, dst = -1, dst2 = -1;
        char pattern[] = "/tmp/systemd-test.xz.XXXXXX",
             pattern2[] = "/tmp/systemd-test.xz.XXXXXX";
        int r;
        _cleanup_free_ char *cmd, *cmd2;
        struct stat st = {};

        log_debug("/* create source from %s */", srcfile);

        assert_se((src = open(srcfile, O_RDONLY|O_CLOEXEC)) >= 0);

        log_debug("/* test compression */");

        assert_se((dst = mkostemp_safe(pattern, O_RDWR|O_CLOEXEC)) >= 0);

        r = compress_stream(src, dst, 1, -1);
        assert(r == 0);

        assert_se(asprintf(&cmd, "xzcat %s | diff %s -", pattern, srcfile) > 0);
        assert_se(system(cmd) == 0);

        log_debug("/* test decompression */");

        assert_se((dst2 = mkostemp_safe(pattern2, O_RDWR|O_CLOEXEC)) >= 0);

        assert_se(stat(srcfile, &st) == 0);

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        r = decompress_stream(dst, dst2, st.st_size);
        assert(r == 0);

        assert_se(asprintf(&cmd2, "diff %s %s", srcfile, pattern2) > 0);
        assert_se(system(cmd2) == 0);

        log_debug("/* test faulty decompression */");

        assert_se(lseek(dst, 1, SEEK_SET) == 1);
        r = decompress_stream(dst, dst2, st.st_size);
        assert(r == -EBADMSG);

        assert_se(lseek(dst, 0, SEEK_SET) == 0);
        assert_se(lseek(dst2, 0, SEEK_SET) == 0);
        r = decompress_stream(dst, dst2, st.st_size - 1);
        assert(r == -E2BIG);

        assert_se(unlink(pattern) == 0);
        assert_se(unlink(pattern2) == 0);
}

int main(int argc, char *argv[]) {

        log_set_max_level(LOG_DEBUG);

        test_compress_uncompress();
        test_uncompress_startswith();
        test_compress_stream(argv[0]);

        return 0;
}
