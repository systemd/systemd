/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "udev-node.h"

static void test_udev_node_escape_path_one(const char *path, const char *expected) {
        char buf[NAME_MAX+1];
        size_t r;

        r = udev_node_escape_path(path, buf, sizeof buf);
        log_debug("udev_node_escape_path(%s) -> %s (expected: %s)", path, buf, expected);
        assert_se(r == strlen(expected));
        assert_se(streq(buf, expected));
}

TEST(udev_node_escape_path) {
        char a[NAME_MAX+1], b[NAME_MAX+1];

        test_udev_node_escape_path_one("/disk/by-id/nvme-eui.1922908022470001001b448b44ccb9d6", "\\x2fdisk\\x2fby-id\\x2fnvme-eui.1922908022470001001b448b44ccb9d6");
        test_udev_node_escape_path_one("/disk/by-id/nvme-eui.1922908022470001001b448b44ccb9d6-part1", "\\x2fdisk\\x2fby-id\\x2fnvme-eui.1922908022470001001b448b44ccb9d6-part1");
        test_udev_node_escape_path_one("/disk/by-id/nvme-eui.1922908022470001001b448b44ccb9d6-part2", "\\x2fdisk\\x2fby-id\\x2fnvme-eui.1922908022470001001b448b44ccb9d6-part2");
        test_udev_node_escape_path_one("/disk/by-id/nvme-WDC_PC_SN720_SDAQNTW-512G-1001_192290802247", "\\x2fdisk\\x2fby-id\\x2fnvme-WDC_PC_SN720_SDAQNTW-512G-1001_192290802247");
        test_udev_node_escape_path_one("/disk/by-id/nvme-WDC_PC_SN720_SDAQNTW-512G-1001_192290802247-part1", "\\x2fdisk\\x2fby-id\\x2fnvme-WDC_PC_SN720_SDAQNTW-512G-1001_192290802247-part1");
        test_udev_node_escape_path_one("/disk/by-id/nvme-WDC_PC_SN720_SDAQNTW-512G-1001_192290802247-part2", "\\x2fdisk\\x2fby-id\\x2fnvme-WDC_PC_SN720_SDAQNTW-512G-1001_192290802247-part2");
        test_udev_node_escape_path_one("/disk/by-id/usb-Generic-_SD_MMC_20120501030900000-0:0", "\\x2fdisk\\x2fby-id\\x2fusb-Generic-_SD_MMC_20120501030900000-0:0");

        memset(a, 'a', sizeof(a) - 1);
        memcpy(a, "/disk/by-id/", strlen("/disk/by-id/"));
        char_array_0(a);

        memset(b, 'a', sizeof(b) - 1);
        memcpy(b, "\\x2fdisk\\x2fby-id\\x2f", strlen("\\x2fdisk\\x2fby-id\\x2f"));
        strcpy(b + sizeof(b) - 12, "N3YhcCqFeID");

        test_udev_node_escape_path_one(a, b);

        strcpy(a + sizeof(a) - 12 - 9, "N3YhcCqFeID");
        strcpy(b + sizeof(b) - 12, "L1oK9iKWdmi");
        test_udev_node_escape_path_one(a, b);

        strcpy(a + sizeof(a) - 12 - 9, "a");
        strcpy(b + sizeof(b) - 12, "A7oaHBRuuZq");
        test_udev_node_escape_path_one(a, b);

        a[sizeof(a) - 12 - 9] = '\0';
        b[sizeof(a) - 12] = '\0';
        test_udev_node_escape_path_one(a, b);
}

DEFINE_TEST_MAIN(LOG_INFO);
