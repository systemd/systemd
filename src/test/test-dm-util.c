/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "dm-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "string-util.h"
#include "tests.h"

#define ROOT_HASH "4a2b7e1c9f0d3e5a6b8c7d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"
#define TABLE "1 7:0 7:1 4096 4096 256 1 sha256 " ROOT_HASH " 9f86d081884c7d659a2feaa0c55ad015"

TEST(dm_verity_table_signed) {
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE, ROOT_HASH));
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE " 2 ignore_zero_blocks check_at_most_once", ROOT_HASH));
        ASSERT_OK_POSITIVE(dm_verity_table_signed(TABLE " 2 root_hash_sig_key_desc cryptsetup:abc-loop0", ROOT_HASH));
        ASSERT_OK_POSITIVE(dm_verity_table_signed(TABLE " 3 ignore_zero_blocks root_hash_sig_key_desc cryptsetup:abc", ROOT_HASH));
        ASSERT_OK_POSITIVE(dm_verity_table_signed(TABLE " 2 root_hash_sig_key_desc cryptsetup:abc", "4A2B7E1C9F0D3E5A6B8C7D9E0F1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C"));
        ASSERT_OK_POSITIVE(dm_verity_table_signed("1 7:0 7:1 4096 4096 256 1 sha256 " ROOT_HASH " - 2 root_hash_sig_key_desc cryptsetup:abc", ROOT_HASH));

        /* The table declares one optional argument. root_hash_sig_key_desc comes after that argument, so
         * it must not mark the table as signed. */
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE " 1 ignore_zero_blocks root_hash_sig_key_desc", ROOT_HASH));

        ASSERT_ERROR(dm_verity_table_signed(TABLE " 2 root_hash_sig_key_desc cryptsetup:abc", "00"), ESTALE);
        ASSERT_ERROR(dm_verity_table_signed("1 7:0 7:1 4096 4096 256 1 sha256", ROOT_HASH), EBADMSG);
        ASSERT_ERROR(dm_verity_table_signed(TABLE " 3 ignore_zero_blocks", ROOT_HASH), EBADMSG);
        ASSERT_ERROR(dm_verity_table_signed(TABLE " x", ROOT_HASH), EINVAL);
}

static void dm_ioctl_init(struct dm_ioctl *dmi, size_t size, const char *name) {
        *dmi = (struct dm_ioctl) {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = size,
                .data_start = sizeof(struct dm_ioctl),
        };
        strncpy_exact(dmi->name, name, sizeof(dmi->name));
}

TEST(dm_open) {
        /* dm_open() must refuse a device whose table is loaded but not active. The kernel creates the device
         * node when the table is loaded, but all I/O on the device fails until the table is activated. We
         * create a device and load a table with the zero target, and check that dm_open() fails with ENXIO.
         * Then we activate the table and check that dm_open() opens the device. */

        _cleanup_close_ int control_fd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *name = NULL, *devname = NULL;
        struct dm_ioctl dmi;
        struct {
                struct dm_ioctl dmi;
                struct dm_target_spec spec;
                char params[8];
        } table;

        ASSERT_OK(asprintf(&name, "test-dm-util-" PID_FMT, getpid()));

        if (geteuid() != 0)
                return (void) log_tests_skipped("not running as root");

        control_fd = xopenat(AT_FDCWD, "/dev/mapper/control", O_RDWR);
        if (control_fd < 0)
                return (void) log_tests_skipped_errno(control_fd, "Failed to open /dev/mapper/control");

        /* The device doesn't exist yet. */
        ASSERT_ERROR(dm_open(name, O_RDONLY|O_CLOEXEC, /* ret_devname= */ NULL), ENXIO);

        /* Create the device and load a table without activating it. */
        dm_ioctl_init(&dmi, sizeof(dmi), name);
        ASSERT_OK_ERRNO(ioctl(control_fd, DM_DEV_CREATE, &dmi));

        dm_ioctl_init(&table.dmi, sizeof(table), name);
        table.dmi.target_count = 1;
        table.spec = (struct dm_target_spec) {
                .length = 8,
                .target_type = "zero",
        };
        zero(table.params);
        ASSERT_OK_ERRNO(ioctl(control_fd, DM_TABLE_LOAD, &table));

        ASSERT_ERROR(dm_open(name, O_RDONLY|O_CLOEXEC, /* ret_devname= */ NULL), ENXIO);

        /* Activate the table. */
        dm_ioctl_init(&dmi, sizeof(dmi), name);
        ASSERT_OK_ERRNO(ioctl(control_fd, DM_DEV_SUSPEND, &dmi));

        fd = ASSERT_OK(dm_open(name, O_RDONLY|O_CLOEXEC, &devname));
        ASSERT_NOT_NULL(devname);

        /* Remove the device. */
        fd = safe_close(fd);
        dm_ioctl_init(&dmi, sizeof(dmi), name);
        ASSERT_OK_ERRNO(ioctl(control_fd, DM_DEV_REMOVE, &dmi));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
