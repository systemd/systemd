/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "missing_socket.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-util.h"

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

        if (connect(fd, &sa.sa, SOCKADDR_LEN(sa)) < 0)
                return log_error_errno(errno, "Failed to connect to vsock:%u:%u: %m", sa.vm.svm_cid, sa.vm.svm_port);

        /* OpenSSH wants us to send a single byte along with the file descriptor, hence do so */
        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* n_iovec= */ 1, /* flags= */ 0);
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

        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* n_iovec= */ 1, /* flags= */ 0);
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

        r = send_one_fd_iov(STDOUT_FILENO, fd, &iovec_nul_byte, /* n_iovec= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent AF_UNIX socket via STDOUT.");
        return 0;
}

static int process_machine(const char *machine, const char *port) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(machine);
        assert(port);

        r = sd_varlink_connect_address(&vl, "/run/systemd/machine/io.systemd.Machine");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machined on /run/systemd/machine/io.systemd.Machine: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        r = varlink_callbo_and_log(
                        vl,
                        "io.systemd.Machine.List",
                        &result,
                        SD_JSON_BUILD_PAIR("name", SD_JSON_BUILD_STRING(machine)));
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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Machine has no AF_VSOCK CID assigned.");

        return process_vsock_cid(cid, port);
}

static int run(int argc, char* argv[]) {

        log_setup();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments: host and port.");

        const char *host = argv[1], *port = argv[2];

        const char *p = startswith(host, "vsock/");
        if (p)
                return process_vsock_string(p, port);

        p = startswith(host, "unix/");
        if (p)
                return process_unix(p);

        p = startswith(host, "vsock-mux/");
        if (p)
                return process_vsock_mux(p, port);

        p = startswith(host, "machine/");
        if (p)
                return process_machine(p, port);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Don't know how to parse host name specification: %s", host);
}

DEFINE_MAIN_FUNCTION(run);
