/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "socket-label.h"
#include "socket-util.h"
#include "string-table.h"
#include "umask-util.h"

static const char* const socket_address_bind_ipv6_only_table[_SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX] = {
        [SOCKET_ADDRESS_DEFAULT]   = "default",
        [SOCKET_ADDRESS_BOTH]      = "both",
        [SOCKET_ADDRESS_IPV6_ONLY] = "ipv6-only"
};

DEFINE_STRING_TABLE_LOOKUP(socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);

SocketAddressBindIPv6Only socket_address_bind_ipv6_only_or_bool_from_string(const char *s) {
        int r;

        r = parse_boolean(s);
        if (r > 0)
                return SOCKET_ADDRESS_IPV6_ONLY;
        if (r == 0)
                return SOCKET_ADDRESS_BOTH;

        return socket_address_bind_ipv6_only_from_string(s);
}

int socket_address_listen(
                const SocketAddress *a,
                int flags,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool reuse_port,
                bool free_bind,
                bool transparent,
                mode_t directory_mode,
                mode_t socket_mode,
                const char *selinux_label,
                const char *smack_label) {

        _cleanup_close_ int fd = -EBADF;
        const char *p;
        int r;

        assert(a);

        r = socket_address_verify(a, true);
        if (r < 0)
                return r;

        if (socket_address_family(a) == AF_INET6 && !socket_ipv6_is_supported())
                return -EAFNOSUPPORT;

        if (selinux_label) {
                r = mac_selinux_create_socket_prepare(selinux_label);
                if (r < 0)
                        return r;
        }

        fd = RET_NERRNO(socket(socket_address_family(a), a->type | flags, a->protocol));

        if (selinux_label)
                mac_selinux_create_socket_clear();

        if (fd < 0)
                return fd;

        if (smack_label) {
                r = mac_smack_apply_fd(fd, SMACK_ATTR_ACCESS, smack_label);
                if (r < 0)
                        log_warning_errno(r, "Failed to apply SMACK label for socket FD, ignoring: %m");
        }

        if (socket_address_family(a) == AF_INET6 && only != SOCKET_ADDRESS_DEFAULT) {
                r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, only == SOCKET_ADDRESS_IPV6_ONLY);
                if (r < 0)
                        return r;
        }

        if (IN_SET(socket_address_family(a), AF_INET, AF_INET6)) {
                if (bind_to_device) {
                        r = socket_bind_to_ifname(fd, bind_to_device);
                        if (r < 0)
                                return r;
                }

                if (reuse_port) {
                        r = setsockopt_int(fd, SOL_SOCKET, SO_REUSEPORT, true);
                        if (r < 0)
                                log_warning_errno(r, "SO_REUSEPORT failed: %m");
                }

                if (free_bind) {
                        r = socket_set_freebind(fd, socket_address_family(a), true);
                        if (r < 0)
                                log_warning_errno(r, "IP_FREEBIND/IPV6_FREEBIND failed: %m");
                }

                if (transparent) {
                        r = socket_set_transparent(fd, socket_address_family(a), true);
                        if (r < 0)
                                log_warning_errno(r, "IP_TRANSPARENT/IPV6_TRANSPARENT failed: %m");
                }
        }

        r = setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        p = socket_address_get_path(a);
        if (p) {
                /* Create parents */
                (void) mkdir_parents_label(p, directory_mode);

                /* Enforce the right access mode for the socket */
                WITH_UMASK(~socket_mode) {
                        r = mac_selinux_bind(fd, &a->sockaddr.sa, a->size);
                        if (r == -EADDRINUSE) {
                                /* Unlink and try again */

                                if (unlink(p) < 0)
                                        return r; /* didn't work, return original error */

                                r = mac_selinux_bind(fd, &a->sockaddr.sa, a->size);
                        }
                        if (r < 0)
                                return r;
                }
                if (smack_label) {
                        r = mac_smack_apply(p, SMACK_ATTR_ACCESS, smack_label);
                        if (r < 0)
                                log_warning_errno(r, "Failed to apply SMACK label for socket path, ignoring: %m");
                }
        } else {
                if (bind(fd, &a->sockaddr.sa, a->size) < 0)
                        return -errno;
        }

        if (socket_address_can_accept(a))
                if (listen(fd, backlog) < 0)
                        return -errno;

        /* Let's trigger an inotify event on the socket node, so that anyone waiting for this socket to be connectable
         * gets notified */
        if (p)
                (void) touch(p);

        return TAKE_FD(fd);
}
