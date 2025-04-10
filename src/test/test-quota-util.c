/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/mman.h>
#include <sys/quota.h>

#include "blockdev-util.h"
#include "device-util.h"
#include "quota-util.h"
#include "tests.h"

#define NUMINTS  (1000)
#define FILESIZE (NUMINTS * sizeof(int))

int *file_nmapped_addr(const char *path);

TEST(quotactl_devnum) {
        _cleanup_free_ char *devnode = NULL;
        int r;
        int fd;
        dev_t devnum;
        int *m_addr;
        const char *path = "/tmp/mmapped.bin";

        int id = getuid();
        ASSERT_OK(id);

        fd = open (path, O_RDWR | O_CREAT | O_TRUNC, 0777 );
        if (fd < 0) {
                ASSERT_TRUE(ERRNO_IS_NOT_SUPPORTED(fd));
                return (void) log_tests_skipped_errno(fd, "Failed to open and create /tmp/mmapped.bin\n");
        }
        ASSERT_OK(fd);
        close(fd);

        m_addr = file_nmapped_addr(path);
        ASSERT_OK(m_addr != NULL);

        r = get_block_device(path, &devnum);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "get_block_device failed\n");
        ASSERT_OK(r);

        r = devname_from_devnum(S_IFBLK, devnum, &devnode);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "devname_from_devnum failed\n");
        ASSERT_OK(r);
        ASSERT_GT(devnum, (long unsigned int) 0);
}

int *file_nmapped_addr(const char *path) {
        int fd;
        int *map_addr;

        fd = open(path, O_RDONLY);
        if (fd == -1) {
                perror("Error opening file for reading");
                return 0;
        }

        map_addr = mmap(0, FILESIZE, PROT_READ, MAP_SHARED, fd, 0);
        if (map_addr == MAP_FAILED) {
                perror("Error mmapping the file");
                return 0;
        }

        close(fd);
        return map_addr;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
