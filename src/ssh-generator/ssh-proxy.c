/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "path-lookup.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

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

        return process_vsock_cid(cid, port);
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

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
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

        *ret = TAKE_PTR(result);
        return 0;
}

static int process_machine(const char *machine, const char *port) {
        int r;

        assert(machine);
        assert(port);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        r = fetch_machine(machine, RUNTIME_SCOPE_USER, &result);
        if (r == -ESRCH)
                r = fetch_machine(machine, RUNTIME_SCOPE_SYSTEM, &result);
        if (r < 0)
                return r;

        uint32_t cid = VMADDR_CID_ANY;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "vSockCid", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint32, 0, 0 },
                {}
        };

        r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &cid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse Varlink reply: %m");

        if (cid == VMADDR_CID_ANY)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Machine %s has no AF_VSOCK CID assigned.", machine);

        return process_vsock_cid(cid, port);
}

static char *startswith_sep(const char *s, const char *prefix) {
        const char *p = startswith(s, prefix);

        if (p && IN_SET(*p, '/', '%'))
                return (char*) p + 1;

        return NULL;
}

static int run(int argc, char* argv[]) {

        log_setup();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments: host and port.");

        const char *host = argv[1], *port = argv[2];

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

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Don't know how to parse host name specification: %s", host);
}

DEFINE_MAIN_FUNCTION(run);
