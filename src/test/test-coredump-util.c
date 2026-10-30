/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>

#include "alloc-util.h"
#include "coredump-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "tests.h"

TEST(coredump_filter_to_from_string) {
        for (CoredumpFilter i = 0; i < _COREDUMP_FILTER_MAX; i++) {
                const char *n;

                ASSERT_NOT_NULL(n = coredump_filter_to_string(i));
                log_info("0x%x\t%s", 1u << i, n);
                ASSERT_EQ(coredump_filter_from_string(n), i);

                uint64_t f;
                ASSERT_OK_ZERO(coredump_filter_mask_from_string(n, &f));
                ASSERT_EQ(f, 1u << i);
        }
}

TEST(coredump_filter_mask_from_string) {
        uint64_t f;
        ASSERT_OK_ZERO(coredump_filter_mask_from_string("default", &f));
        ASSERT_EQ(f, COREDUMP_FILTER_MASK_DEFAULT);
        ASSERT_OK_ZERO(coredump_filter_mask_from_string("all", &f));
        ASSERT_EQ(f, COREDUMP_FILTER_MASK_ALL);

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("  default\tdefault\tdefault  ", &f));
        ASSERT_EQ(f, COREDUMP_FILTER_MASK_DEFAULT);

        ASSERT_FAIL(coredump_filter_mask_from_string("defaulta", &f));
        ASSERT_FAIL(coredump_filter_mask_from_string("default defaulta default", &f));
        ASSERT_FAIL(coredump_filter_mask_from_string("default default defaulta", &f));

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("private-anonymous default", &f));
        ASSERT_EQ(f, COREDUMP_FILTER_MASK_DEFAULT);

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("shared-file-backed shared-dax", &f));
        ASSERT_EQ(f, (UINT64_C(1) << COREDUMP_FILTER_SHARED_FILE_BACKED |
                      UINT64_C(1) << COREDUMP_FILTER_SHARED_DAX));

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("private-file-backed private-dax 0xF", &f));
        ASSERT_EQ(f, (UINT64_C(1) << COREDUMP_FILTER_PRIVATE_FILE_BACKED |
                      UINT64_C(1) << COREDUMP_FILTER_PRIVATE_DAX |
                      0xF));

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("11", &f));
        ASSERT_EQ(f, 0x11U);

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("0x1101", &f));
        ASSERT_EQ(f, 0x1101U);

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("0", &f));
        ASSERT_EQ(f, 0U);

        ASSERT_OK_ZERO(coredump_filter_mask_from_string("all", &f));
        ASSERT_TRUE(FLAGS_SET(f, (1 << COREDUMP_FILTER_PRIVATE_ANONYMOUS |
                                  1 << COREDUMP_FILTER_SHARED_ANONYMOUS |
                                  1 << COREDUMP_FILTER_PRIVATE_FILE_BACKED |
                                  1 << COREDUMP_FILTER_SHARED_FILE_BACKED |
                                  1 << COREDUMP_FILTER_ELF_HEADERS |
                                  1 << COREDUMP_FILTER_PRIVATE_HUGE |
                                  1 << COREDUMP_FILTER_SHARED_HUGE |
                                  1 << COREDUMP_FILTER_PRIVATE_DAX |
                                  1 << COREDUMP_FILTER_SHARED_DAX)));
}

static void test_parse_auxv_two(
                uint8_t elf_class,
                size_t offset,
                const char *data,
                size_t data_size,
                int expect_at_secure,
                uid_t expect_uid,
                uid_t expect_euid,
                gid_t expect_gid,
                gid_t expect_egid) {

        int at_secure;
        uid_t uid, euid;
        gid_t gid, egid;
        ASSERT_OK_ZERO(parse_auxv(LOG_ERR, elf_class, data, data_size,
                                  &at_secure, &uid, &euid, &gid, &egid));

        log_debug("[offset=%zu] at_secure=%d, uid="UID_FMT", euid="UID_FMT", gid="GID_FMT", egid="GID_FMT,
                  offset,
                  at_secure, uid, euid, gid, egid);

        ASSERT_EQ(uid, expect_uid);
        ASSERT_EQ(euid, expect_euid);
        ASSERT_EQ(gid, expect_gid);
        ASSERT_EQ(egid, expect_egid);
}

static void test_parse_auxv_one(
                uint8_t elf_class,
                int dir_fd,
                const char *filename,
                int expect_at_secure,
                uid_t expect_uid,
                uid_t expect_euid,
                gid_t expect_gid,
                gid_t expect_egid) {

        _cleanup_free_ char *buf;
        const char *data;
        size_t data_size;
        log_info("Parsing %s…", filename);
        ASSERT_OK(read_full_file_at(dir_fd, filename, &buf, &data_size));

        for (size_t offset = 0; offset < 8; offset++) {
                _cleanup_free_ char *buf2 = NULL;

                if (offset == 0)
                        data = buf;
                else {
                        ASSERT_NOT_NULL(buf2 = malloc(offset + data_size));
                        memcpy(buf2 + offset, buf, data_size);
                        data = buf2 + offset;
                }

                test_parse_auxv_two(elf_class, offset, data, data_size,
                                    expect_at_secure, expect_uid, expect_euid, expect_gid, expect_egid);
        }
}

TEST(parse_auxv) {
        _cleanup_free_ char *dir = NULL;
        _cleanup_close_ int dir_fd = -EBADF;

        ASSERT_OK(get_testdata_dir("auxv", &dir));
        dir_fd = ASSERT_OK_ERRNO(open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_PATH));

        if (__BYTE_ORDER == __LITTLE_ENDIAN) {
                test_parse_auxv_one(ELFCLASS32, dir_fd, "resolved.arm32", /* expect_at_secure= */ 0, 193, 193, 193, 193);
                test_parse_auxv_one(ELFCLASS64, dir_fd, "bash.riscv64", /* expect_at_secure= */ 0, 1001, 1001, 1001, 1001);
                test_parse_auxv_one(ELFCLASS32, dir_fd, "sleep.i686", /* expect_at_secure= */ 0, 1000, 1000, 1000, 1000);
                /* after chgrp and chmod g+s */
                test_parse_auxv_one(ELFCLASS32, dir_fd, "sleep32.i686", 1, 1000, 1000, 1000, 10);
                test_parse_auxv_one(ELFCLASS64, dir_fd, "sleep64.amd64", 1, 1000, 1000, 1000, 10);

                test_parse_auxv_one(ELFCLASS64, dir_fd, "sudo.aarch64", 1, 1494200408, /* expect_euid= */ 0, 1494200408, 1494200408);
                test_parse_auxv_one(ELFCLASS64, dir_fd, "sudo.amd64", 1, 1000, /* expect_euid= */ 0, 1000, 1000);

                /* Those run unprivileged, but start as root. */
                test_parse_auxv_one(ELFCLASS64, dir_fd, "dbus-broker-launch.amd64", /* expect_at_secure= */ 0, /* expect_uid= */ 0, /* expect_euid= */ 0, /* expect_gid= */ 0, /* expect_egid= */ 0);
                test_parse_auxv_one(ELFCLASS64, dir_fd, "dbus-broker-launch.aarch64", /* expect_at_secure= */ 0, /* expect_uid= */ 0, /* expect_euid= */ 0, /* expect_gid= */ 0, /* expect_egid= */ 0);
                test_parse_auxv_one(ELFCLASS64, dir_fd, "polkitd.aarch64", /* expect_at_secure= */ 0, /* expect_uid= */ 0, /* expect_euid= */ 0, /* expect_gid= */ 0, /* expect_egid= */ 0);
        } else {
                test_parse_auxv_one(ELFCLASS64, dir_fd, "cat.s390x", /* expect_at_secure= */ 0, 3481, 3481, 3481, 3481);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
