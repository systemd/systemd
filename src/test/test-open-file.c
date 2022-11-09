
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "open-file.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_open_file) {
    OpenFile openfile;
    int r;

    r = parse_open_file("/proc/1/ns/mnt:host-mount-namespace:ro", &openfile);

    assert_se(r == 0);
    assert_se(streq(openfile.path, "/proc/1/ns/mnt"));
    assert_se(streq(openfile.fdname, "host-mount-namespace"));
    assert_se(openfile.flags == O_RDONLY);

    r = parse_open_file("/proc/1/ns/mnt::rw", &openfile);

    assert_se(r == 0);
    assert_se(streq(openfile.path, "/proc/1/ns/mnt"));
    assert_se(streq(openfile.fdname, ""));
    assert_se(openfile.flags == O_RDWR);
}

DEFINE_TEST_MAIN(LOG_INFO);
