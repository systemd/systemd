/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netdb.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "verbs.h"

COMMAND(
        "systemd-ssh-proxy\0",
        "Connect an SSH client to AF_VSOCK, AF_UNIX and MPTCP sockets.",
        .argspec = "HOST PORT\0",
        .man_page = "systemd-ssh-proxy(1)",
        .option_namespace = "common",
);

#define HEADER_READ_TIMEOUT_USEC (5 * USEC_PER_SEC)

static int process_vsock_cid(unsigned cid, const char *port) {
        int r;

        assert(cid != VMADDR_CID_ANY);
        assert(port);

        union sockaddr_union sa = {
                .vm.svm_cid = cid,
                .vm.svm_family = AF_VSOCK,
        };

        r = vsock_parse_port(port, &sa.vm.svm_port);
        if (r < 0)
                return log_error_errno(r, "Failed to parse vsock port: %s", port);

        _cleanup_close_ int fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate AF_VSOCK socket: %m");

        if (connect(fd, &sa.sa, sockaddr_len(&sa)) < 0)
                return log_error_errno(errno, "Failed to connect to vsock:%u:%u: %m", sa.vm.svm_cid, sa.vm.svm_port);

        /* OpenSSH wants us to send a single byte along with the file descriptor, hence do so */
        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* iovlen= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent AF_VSOCK socket via STDOUT.");
        return 0;
}

static int process_vsock_string(const char *host, const char *port) {
        unsigned cid;
        int r;

        assert(host);
        assert(port);

        r = vsock_parse_cid(host, &cid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse vsock cid: %s", host);

        if (cid == VMADDR_CID_ANY)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use VMADDR_CID_ANY to connect to a remote host.");

        return process_vsock_cid(cid, port);
}

static int connect_mptcp(const union sockaddr_union *sa, socklen_t salen) {
        int r;

        assert(sa);
        assert(IN_SET(sa->sa.sa_family, AF_INET, AF_INET6));

        /* Note that this logs only at debug level, since the caller might try multiple addresses in a
         * row, and only the final failure should be reported to the user. */

        _cleanup_free_ char *pretty = NULL;
        r = sockaddr_pretty(&sa->sa, salen, /* translate_ipv6= */ true, /* include_port= */ true, &pretty);
        if (r < 0)
                return log_oom_debug();

        _cleanup_close_ int fd = socket(sa->sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_MPTCP);
        if (fd < 0) {
                /* The kernel was built without MPTCP support (EPROTONOSUPPORT), it has been turned off for
                 * the network namespace via net.mptcp.enabled=0 (ENOPROTOOPT), or it is blocked in some
                 * other way (for example by a seccomp filter returning some other "not supported"
                 * error). In that case, fall back to plain TCP. Note that if the peer doesn't support MPTCP
                 * the kernel will transparently fall back to TCP on its own during connection setup. */
                if (!ERRNO_IS_NOT_SUPPORTED(errno))
                        return log_debug_errno(errno, "Failed to allocate MPTCP socket: %m");

                log_debug_errno(errno, "MPTCP not available, falling back to TCP: %m");

                fd = socket(sa->sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP);
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to allocate TCP socket: %m");
        }

        /* ssh only enables SO_KEEPALIVE (as per TCPKeepAlive=yes) on sockets it connects itself, not on
         * those it receives via ProxyUseFdpass, hence do it here. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to enable SO_KEEPALIVE: %m");

        log_debug("Connecting to %s...", pretty);

        if (connect(fd, &sa->sa, salen) < 0)
                return log_debug_errno(errno, "Failed to connect to %s: %m", pretty);

        return TAKE_FD(fd);
}

static int process_mptcp(const char *host, const char *port) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(host);
        assert(port);

        uint16_t port_number;
        r = parse_ip_port(port, &port_number);
        if (r < 0)
                return log_error_errno(r, "Failed to parse IP port: %s", port);

        union in_addr_union a;
        int family, ifindex = 0;
        r = in_addr_ifindex_from_string_auto(host, &family, &a, &ifindex);
        if (r == -ENODEV)
                return log_error_errno(r, "Network interface of '%s' does not exist.", host);
        if (r < 0 && r != -EINVAL)
                return log_error_errno(r, "Failed to parse IP address '%s': %m", host);
        if (r >= 0) {
                /* A literal IP address (possibly with an interface suffix) was specified. The interface
                 * suffix only has an effect on IPv6 link-local addresses (as sin6_scope_id), hence refuse
                 * it otherwise, instead of silently ignoring it. */
                if (ifindex > 0 && (family != AF_INET6 || !in6_addr_is_link_local(&a.in6)))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Interface suffix is only supported for IPv6 link-local addresses: %s", host);

                union sockaddr_union sa;
                r = sockaddr_set_in_addr(&sa, family, &a, port_number);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize socket address: %m");
                if (family == AF_INET6)
                        sa.in6.sin6_scope_id = ifindex;

                fd = connect_mptcp(&sa, sockaddr_len(&sa));
                if (fd < 0)
                        return log_error_errno(fd, "Failed to connect to '%s': %m", host);
        } else {
                /* Otherwise, resolve the host name, and try all returned addresses in order */
                struct addrinfo hints = {
                        .ai_family = AF_UNSPEC,
                        .ai_socktype = SOCK_STREAM,
                        .ai_flags = AI_ADDRCONFIG|AI_NUMERICSERV,
                };
                struct addrinfo *result = NULL;

                r = getaddrinfo(host, port, &hints, &result);
                if (r == EAI_SYSTEM)
                        return log_error_errno(errno, "Failed to resolve host '%s': %m", host);
                if (r != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                               "Failed to resolve host '%s': %s", host, gai_strerror(r));

                bool tried = false;
                for (struct addrinfo *i = result; i; i = i->ai_next) {
                        if (!IN_SET(i->ai_family, AF_INET, AF_INET6) ||
                            i->ai_addrlen > sizeof(union sockaddr_union))
                                continue;

                        union sockaddr_union sa = {};
                        memcpy(&sa, i->ai_addr, i->ai_addrlen);

                        tried = true;
                        fd = connect_mptcp(&sa, i->ai_addrlen);
                        if (fd >= 0)
                                break;
                }

                freeaddrinfo(result);

                if (!tried)
                        return log_error_errno(SYNTHETIC_ERRNO(EADDRNOTAVAIL), "Host '%s' resolved to no usable addresses.", host);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to connect to any address of host '%s', last error: %m", host);
        }

        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* iovlen= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent IP socket via STDOUT.");
        return 0;
}

static int process_unix(const char *path) {
        int r;

        assert(path);

        /* We assume the path is absolute unless it starts with a dot (or is already explicitly absolute) */
        _cleanup_free_ char *prefixed = NULL;
        if (!STARTSWITH_SET(path, "/", "./")) {
                prefixed = strjoin("/", path);
                if (!prefixed)
                        return log_oom();

                path = prefixed;
        }

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate AF_UNIX socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to AF_UNIX socket %s: %m", path);

        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* iovlen= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent AF_UNIX socket via STDOUT.");
        return 0;
}

static int skip_ok_port_res(int fd, const char *path, const char *port) {
        struct timeval oldtv;
        socklen_t oldtv_size = sizeof(oldtv);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &oldtv, &oldtv_size) < 0)
                return log_error_errno(errno, "Failed to get socket receive timeout for %s: %m", path);
        if (oldtv_size != sizeof(oldtv))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Unexpected size of socket receive timeout for %s", path);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, TIMEVAL_STORE(HEADER_READ_TIMEOUT_USEC), sizeof(struct timeval)) < 0)
                return log_error_errno(errno, "Failed to set socket receive timeout for %s: %m", path);

        char recv_buf[STRLEN("OK 65535\n")];
        size_t bytes_recv = 0, bytes_avail = 0, pos = 0;
        static const char expected_prefix[] = "OK ";

        for (;;) {
                if (pos >= bytes_avail) {
                        assert(bytes_recv <= bytes_avail);
                        if (bytes_avail >= sizeof(recv_buf)) {
                                /*
                                  Full buffer means that we have peeked as many bytes as possible and not seeing the ending \n .
                                  So the server is believed to not send OK PORT response, and we just pass out the socket to ssh client,
                                  and let it handle the connection.

                                  If we have not received any bytes from the socket buffer, we can safely pass out the socket,
                                  since no change has been made to the socket buffer. Otherwise, if some bytes have been received,
                                  the socket buffer has been changed, the only option is to give up and terminate the connection.
                                  Similar logic applies below when we meet other kinds of unexpected responses.
                                */
                                if (bytes_recv == 0) {
                                        log_debug("Received too many bytes while waiting for OK PORT response from %s\n"
                                                  "Assume the multiplexer is not sending OK PORT.",
                                                  path);
                                        goto passout_fd;
                                }
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Received too many bytes while waiting for OK PORT response from %s", path);
                        }
                        if (bytes_avail > bytes_recv) {
                                /*
                                  Discard already peeked bytes before peeking more.

                                  XXX: We cannot use SO_RCVLOWAT to set the minimum number of bytes to be peeked to peek entire
                                       OK PORT response at once to prevent changes to the recving buffer, because SO_RCVLOWAT
                                       does not work on unix sockets with recv(..., MSG_PEEK). Also poll() does not help here,
                                       because poll() returns readable as long as there is any data in the socket buffer for
                                       unix sockets, not respecting SO_RCVLOWAT.

                                  XXX: We could have used SO_PEEK_OFF to continuously peek more data without changing the socket
                                       receive buffer, but this function breaks since Linux 4.3 due to a kernel bug, which is fixed
                                       in Linux 6.18 commit 7bf3a476ce43 ("af_unix: Read sk_peek_offset() again after sleeping in
                                       unix_stream_read_generic()."). It is also not possible to detect whether the kernel is
                                       affected by this bug at runtime.

                                  As a result, we have no other choice but to discard already peeked data here.
                                */
                                ssize_t rlen = recv(fd, recv_buf + bytes_recv, bytes_avail - bytes_recv, /* flags= */ 0);
                                if (rlen < 0)
                                        return log_error_errno(errno, "Failed to discard OK PORT response from %s: %m", path);
                                if ((size_t) rlen != bytes_avail - bytes_recv)
                                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while discarding OK PORT response from %s", path);
                                log_debug("Successfully discarded %zi bytes of response: %.*s", rlen, (int) rlen, recv_buf + bytes_recv);
                                bytes_recv = bytes_avail;
                        }
                        ssize_t len = recv(fd, recv_buf + bytes_avail, sizeof(recv_buf) - bytes_avail, MSG_PEEK);
                        if (len < 0) {
                                if (errno != EAGAIN)
                                        return log_error_errno(errno, "Failed to receive OK from %s: %m", path);
                                if (bytes_recv == 0) {
                                        log_debug("Timeout while waiting for OK PORT response from %s\n"
                                                  "Assume the multiplexer will not send OK PORT.",
                                                  path);
                                        goto passout_fd;
                                }
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Timed out to receive OK PORT from %s", path);

                        }
                        if (len == 0) {
                                log_debug("Connection closed while waiting for OK PORT response from %s", path);
                                if (bytes_recv == 0) {
                                        log_debug("No data received, which means the connecting port is not open.");
                                        return log_error_errno(SYNTHETIC_ERRNO(ECONNREFUSED), "Port %s on %s is not open", port, path);
                                }
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Connection closed before full OK PORT response received from %s.", path);
                        }
                        bytes_avail += len;
                }
                assert(pos < bytes_avail);
                if (pos < strlen(expected_prefix) && recv_buf[pos] != expected_prefix[pos]) {
                        if (bytes_recv == 0) {
                                log_debug("Received response does not start with expected OK PORT response from %s\n"
                                          "Assume the multiplexer will not send OK PORT.",
                                          path);
                                goto passout_fd;
                        }
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Received invalid response while waiting for OK PORT from %s", path);
                }
                if (recv_buf[pos] == '\n') {
                        pos += 1;
                        break;
                }
                pos += 1;
        }

        assert(pos <= sizeof(recv_buf));
        assert(bytes_recv <= pos);
        if (bytes_recv < pos) {
                ssize_t len = recv(fd, recv_buf + bytes_recv, pos - bytes_recv, /* flags= */ 0);
                if (len < 0)
                        return log_error_errno(errno, "Failed to discard OK PORT response from %s: %m", path);
                if ((size_t) len != pos - bytes_recv)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while discarding OK PORT response from %s", path);
                log_debug("Successfully discarded response from %s: %.*s", path, (int) pos, recv_buf);
        }

passout_fd:
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &oldtv, sizeof(oldtv)) < 0)
                return log_error_errno(errno, "Failed to restore socket receive timeout for %s: %m", path);
        return 0;
}

static int process_vsock_mux(const char *path, const char *port) {
        int r;

        assert(path);
        assert(port);

        /* We assume the path is absolute unless it starts with a dot (or is already explicitly absolute) */
        _cleanup_free_ char *prefixed = NULL;
        if (!STARTSWITH_SET(path, "/", "./")) {
                prefixed = strjoin("/", path);
                if (!prefixed)
                        return log_oom();

                path = prefixed;
        }

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate AF_UNIX socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to AF_UNIX socket %s: %m", path);

        /* Based on the protocol as defined here:
         * https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/vsock.md
         * https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md */
        _cleanup_free_ char *connect_cmd = NULL;
        connect_cmd = strjoin("CONNECT ", port, "\n");
        if (!connect_cmd)
                return log_oom();

        r = loop_write(fd, connect_cmd, SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to send CONNECT to %s:%s: %m", path, port);

        r = skip_ok_port_res(fd, path, port);
        if (r < 0)
                return r;

        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* iovlen= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent AF_UNIX socket via STDOUT.");
        return 0;
}

static int fetch_machine(const char *machine, RuntimeScope scope, sd_json_variant **ret) {
        int r;

        assert(machine);
        assert(ret);

        _cleanup_free_ char *addr = NULL;
        r = runtime_directory_generic(scope, "systemd/machine/io.systemd.Machine", &addr);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, addr);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machined on %s: %m", addr);

        sd_json_variant *result = NULL;
        const char *error_id;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Machine.List",
                        &result,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", machine));
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.Machine.List() varlink call: %m");
        if (error_id) {
                if (streq(error_id, "io.systemd.Machine.NoSuchMachine"))
                        return -ESRCH;

                r = sd_varlink_error_to_errno(error_id, result); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return log_error_errno(r, "Failed to issue io.systemd.Machine.List() varlink call: %m");

                return log_error_errno(r, "Failed to issue io.systemd.Machine.List() varlink call: %s", error_id);
        }

        /* result is a borrowed reference into the varlink connection's receive buffer. Take a real ref so
         * that it survives the cleanup of vl below. */
        *ret = sd_json_variant_ref(result);
        return 0;
}

static int process_machine(const char *machine, const char *port) {
        int r;

        assert(machine);
        assert(port);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        RuntimeScope scope = RUNTIME_SCOPE_USER;
        r = fetch_machine(machine, scope, &result);
        if (r == -ESRCH) {
                scope = RUNTIME_SCOPE_SYSTEM;
                r = fetch_machine(machine, scope, &result);
        }
        if (r < 0)
                return r;

        struct {
                uint32_t cid;
                const char *class;
                const char *service;
        } p = {
                .cid = VMADDR_CID_ANY,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "vSockCid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32,       voffsetof(p, cid),     0                 },
                { "class",    SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, voffsetof(p, class),   SD_JSON_MANDATORY },
                { "service",  SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, voffsetof(p, service), 0                 },
                {}
        };

        r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to parse Varlink reply: %m");

        if (streq(p.class, "container")) {
                _cleanup_free_ char *path = NULL;

                if (!streq_ptr(p.service, "systemd-nspawn"))
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Don't know how to SSH into '%s' container %s.", p.service, machine);

                r = runtime_directory_generic(scope, "systemd/nspawn", &path);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine runtime directory: %m");

                if (!path_extend(&path, machine, "unix-export", "ssh"))
                        return log_oom();

                r = is_socket(path);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if '%s' exists and is a socket: %m", path);
                if (r == 0)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(ENOENT),
                                        "'%s' does not exist or is not a socket, are sshd and systemd-ssh-generator installed and enabled in the container?",
                                        path);

                return process_unix(path);
        }

        if (!streq(p.class, "vm"))
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE), "Don't know how to SSH into machine %s with class '%s'.", machine, p.class);

        if (p.cid == VMADDR_CID_ANY)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Machine %s has no AF_VSOCK CID assigned.", machine);

        return process_vsock_cid(p.cid, port);
}

static char *startswith_sep(const char *s, const char *prefix) {
        const char *p = startswith(s, prefix);

        if (p && IN_SET(*p, '/', '%'))
                return (char*) p + 1;

        return NULL;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = common_parse_argv_full(argc, argv, /* min_args= */ 2, /* max_args= */ 2, &args);
        if (r <= 0)
                return r;

        const char *host = args[0], *port = args[1];

        const char *p = startswith_sep(host, "vsock");
        if (p)
                return process_vsock_string(p, port);

        p = startswith_sep(host, "unix");
        if (p)
                return process_unix(p);

        p = startswith_sep(host, "vsock-mux");
        if (p)
                return process_vsock_mux(p, port);

        p = startswith_sep(host, "machine");
        if (p)
                return process_machine(p, port);

        p = startswith_sep(host, "mptcp");
        if (p)
                return process_mptcp(p, port);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Don't know how to parse host name specification: %s", host);
}

DEFINE_MAIN_FUNCTION(run);
