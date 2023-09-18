/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "btrfs-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t offset;
        int r;

        assert(argc == 2);
        assert(!isempty(argv[1]));

        fd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                log_error_errno(fd, "Failed to open '%s': %m", argv[1]);
                return EXIT_FAILURE;
        }

        r = btrfs_get_file_physical_offset_fd(fd, &offset);
        if (r < 0) {
                log_error_errno(fd, "Failed to get physical offset of '%s': %m", argv[1]);
                return EXIT_FAILURE;
        }

        printf("%" PRIu64 "\n", offset);
        return EXIT_SUCCESS;
}
