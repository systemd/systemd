/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fd-util.h"
#include "log.h"
#include "qcow2-util.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int sfd = -1, dfd = -1;
        int r;

        if (argc != 3) {
                log_error("Needs two arguments.");
                return EXIT_FAILURE;
        }

        sfd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (sfd < 0) {
                log_error_errno(errno, "Can't open source file: %m");
                return EXIT_FAILURE;
        }

        dfd = open(argv[2], O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, 0666);
        if (dfd < 0) {
                log_error_errno(errno, "Can't open destination file: %m");
                return EXIT_FAILURE;
        }

        r = qcow2_convert(sfd, dfd);
        if (r < 0) {
                log_error_errno(r, "Failed to unpack: %m");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
