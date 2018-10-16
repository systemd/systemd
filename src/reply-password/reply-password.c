/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "fd-util.h"
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
        _cleanup_close_ int fd = -1;
        char packet[LINE_MAX];
        size_t length;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 3) {
                log_error("Wrong number of arguments.");
                return EXIT_FAILURE;
        }

        if (streq(argv[1], "1")) {

                packet[0] = '+';
                if (!fgets(packet+1, sizeof(packet)-1, stdin)) {
                        r = log_error_errno(errno, "Failed to read password: %m");
                        goto finish;
                }

                truncate_nl(packet+1);
                length = 1 + strlen(packet+1) + 1;
        } else if (streq(argv[1], "0")) {
                packet[0] = '-';
                length = 1;
        } else {
                log_error("Invalid first argument %s", argv[1]);
                r = -EINVAL;
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                r = log_error_errno(errno, "socket() failed: %m");
                goto finish;
        }

        r = send_on_socket(fd, argv[2], packet, length);

finish:
        explicit_bzero(packet, sizeof(packet));

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
