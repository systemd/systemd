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

        struct timeval oldtv;
        {
                socklen_t oldtv_size = sizeof(oldtv);
                r = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &oldtv, &oldtv_size);
                if (r < 0)
                        return log_error_errno(errno, "Failed to get socket receive timeout for %s: %m", path);
                if (oldtv_size != sizeof(oldtv))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Unexpected size of socket receive timeout for %s: %m", path);
        }
        {
                struct timeval newtv = {
                        .tv_sec = 5,
                        .tv_usec = 0,
                };
                r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &newtv, sizeof(newtv));
                if (r < 0)
                        return log_error_errno(errno, "Failed to set socket receive timeout for %s: %m", path);
        }

        /* 10 is the size of "OK 65535\n" */
        char recv_buf[10];
        size_t bytes_recv = 0;
        size_t bytes_avail = 0;
        size_t pos = 0;
        const char expected_prefix[] = "OK ";
        const size_t expected_prefix_len = strlen(expected_prefix);

        for (;;) {
                if (pos >= bytes_avail) {
                        assert(bytes_recv <= bytes_avail);
                        if (bytes_avail < sizeof(recv_buf)) {
                                if (bytes_avail > bytes_recv) {
                                        ssize_t rlen = recv(fd, recv_buf + bytes_recv, bytes_avail - bytes_recv, 0);
                                        if (rlen < 0)
                                                return log_error_errno(errno, "Failed to discard OK PORT response from %s: %m", path);
                                        else if ((size_t) rlen != bytes_avail - bytes_recv)
                                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while discarding OK PORT response from %s: %m", path);
                                        log_debug("Successfully discarded %ld bytes of response: %.*s", rlen, (int) rlen, recv_buf + bytes_recv);
                                        bytes_recv = bytes_avail;
                                }
                                ssize_t len = recv(fd, recv_buf + bytes_avail, sizeof(recv_buf) - bytes_avail, MSG_PEEK);
                                if (len < 0) {
                                        if (errno == EAGAIN) {
                                                if (bytes_recv == 0) {
                                                        log_debug("Timeout while waiting for OK PORT response from %s", path);
                                                        log_debug("Assume the multiplexer will not send OK PORT.");
                                                        goto passout_fd;
                                                } else
                                                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Timed out to receive OK PORT from %s: %m", path);
                                        } else
                                                return log_error_errno(errno, "Failed to receive OK from %s: %m", path);
                                } else if (len == 0) {
                                        log_debug("Connection closed while waiting for OK PORT response from %s", path);
                                        if (bytes_recv == 0) {
                                                log_debug("No data received, which means the connecting port is not open.");
                                                return log_error_errno(SYNTHETIC_ERRNO(ECONNREFUSED), "Port %s on %s is not open", port, path);
                                        } else
                                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Connection closed before full OK PORT response received from %s.", path);
                                }
                                bytes_avail += len;
                        } else {
                                if (bytes_recv == 0){
                                        log_debug("Received too many bytes while waiting for OK PORT response from %s", path);
                                        log_debug("Assume the multiplexer is not sending OK PORT.");
                                        goto passout_fd;
                                } else
                                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Received too many bytes while waiting for OK PORT response from %s", path);
                        }
                }
                assert(pos < bytes_avail);
                if (pos < expected_prefix_len && recv_buf[pos] != expected_prefix[pos]) {
                        if (bytes_recv == 0) {
                                log_debug("Received response does not start with expected OK PORT response from %s", path);
                                log_debug("Assume the multiplexer will not send OK PORT.");
                                goto passout_fd;
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Received invalid response while waiting for OK PORT from %s", path);
                } else if (recv_buf[pos] == '\n') {
                        pos += 1;
                        break;
                }
                pos += 1;
        }

        {
                char buf_discard[sizeof(recv_buf)];
                assert(pos <= sizeof(buf_discard));
                assert(bytes_recv <= pos);
                if (bytes_recv < pos) {
                        ssize_t len = recv(fd, buf_discard, pos - bytes_recv, 0);
                        if (len < 0)
                                return log_error_errno(errno, "Failed to discard OK PORT response from %s: %m", path);
                        if ((size_t) len != pos - bytes_recv)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while discarding OK PORT response from %s: %m", path);
                        log_debug("Successfully discarded response from %s: %.*s", path, (int) pos, buf_discard);
                }
        }

passout_fd:
        {
                r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &oldtv, sizeof(oldtv));
                if (r < 0)
                        return log_error_errno(errno, "Failed to restore socket receive timeout for %s: %m", path);
        }

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
        r = runtime_directory_generic(scope, "machine/io.systemd.Machine", &addr);
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
