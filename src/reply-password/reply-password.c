/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "alloc-util.h"
#include "main-func.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"

static int send_on_socket(int fd, const char *socket_name, const void *packet, size_t size) {
        union sockaddr_union sa = {};
        int salen;

        assert(fd >= 0);
        assert(socket_name);
        assert(packet);

        salen = sockaddr_un_set_path(&sa.un, socket_name);
        if (salen < 0)
                return log_error_errno(salen, "Specified socket path for AF_UNIX socket invalid, refusing: %s", socket_name);

        if (sendto(fd, packet, size, MSG_NOSIGNAL, &sa.sa, salen) < 0)
                return log_error_errno(errno, "Failed to send: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(erase_and_freep) char *packet = NULL;
        _cleanup_close_ int fd = -1;
        size_t length = 0;
        int r;

        log_setup_service();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Wrong number of arguments.");

        if (streq(argv[1], "1")) {
                _cleanup_(erase_and_freep) char *line = NULL;

                r = read_line(stdin, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read password: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Got EOF while reading password.");

                packet = strjoin("+", line);
                if (!packet)
                        return log_oom();

                length = 1 + strlen(line) + 1;

        } else if (streq(argv[1], "0")) {
                packet = strdup("-");
                if (!packet)
                        return log_oom();

                length = 1;

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid first argument %s", argv[1]);

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "socket() failed: %m");

        return send_on_socket(fd, argv[2], packet, length);
}

DEFINE_MAIN_FUNCTION(run);
