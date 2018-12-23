/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
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

int main(int argc, char *argv[]) {
        _cleanup_free_ char *packet = NULL;
        _cleanup_close_ int fd = -1;
        size_t length = 0;
        int r;

        log_setup_service();

        if (argc != 3) {
                log_error("Wrong number of arguments.");
                return EXIT_FAILURE;
        }

        if (streq(argv[1], "1")) {
                _cleanup_string_free_erase_ char *line = NULL;

                r = read_line(stdin, LONG_LINE_MAX, &line);
                if (r < 0) {
                        log_error_errno(r, "Failed to read password: %m");
                        goto finish;
                }
                if (r == 0) {
                        log_error("Got EOF while reading password.");
                        r = -EIO;
                        goto finish;
                }

                packet = strjoin("+", line);
                if (!packet) {
                        r = log_oom();
                        goto finish;
                }

                length = 1 + strlen(line) + 1;

        } else if (streq(argv[1], "0")) {
                packet = strdup("-");
                if (!packet) {
                        r = log_oom();
                        goto finish;
                }

                length = 1;

        } else {
                log_error("Invalid first argument %s", argv[1]);
                r = -EINVAL;
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
                r = log_error_errno(errno, "socket() failed: %m");
                goto finish;
        }

        r = send_on_socket(fd, argv[2], packet, length);

finish:
        explicit_bzero_safe(packet, length);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
