/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "alloc-util.h"
#include "bpf-unix-socket-protocol.h"

#if BPF_FRAMEWORK
/* libbpf, clang, llvm and bpftool compile time dependencies are satisfied */
#include "bpf-util.h"
#include "bpf-link.h"
#include "mkdir.h"
#include "unix-socket-protocol-api.bpf.h"
#include "unix-socket-protocol-skel.h"

#define UNIX_SOCKET_PROTOCOL_MAP_PIN_PREFIX "/sys/fs/bpf/systemd/unix-socket-protocol/maps"

int unix_socket_protocol_bpf_supported(void) {
        static int supported = -1;

        if (supported >= 0)
                return supported;

        if (dlopen_bpf(LOG_WARNING) < 0)
                return (supported = false);

        return (supported = true);
}

struct unix_socket_protocol_bpf* unix_socket_protocol_bpf_destroy(struct unix_socket_protocol_bpf *obj) {
        /* unix_socket_protocol_bpf__destroy handles object == NULL case */
        unix_socket_protocol_bpf__destroy(obj);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct unix_socket_protocol_bpf *, unix_socket_protocol_bpf_destroy);

static int unix_socket_protocol_bpf_prepare(struct unix_socket_protocol_bpf *obj) {
        int r;

        (void) mkdir_p(UNIX_SOCKET_PROTOCOL_MAP_PIN_PREFIX, 0755);

        r = sym_bpf_map__set_pin_path(obj->maps.unix_socket_protocol_ino_map,
                                      UNIX_SOCKET_PROTOCOL_MAP_PIN_PREFIX "/unix_socket_protocol_ino_map");
        if (r < 0)
                return log_error_errno(r, "bpf-unix-socket-protocol: Failed to set pin path: %m");

        r = unix_socket_protocol_bpf__load(obj);
        if (r < 0)
                return log_debug_errno(r, "bpf-unix-socket-protocol: Failed to load BPF object: %m");

        r = sym_bpf_object__pin_maps(obj->obj, NULL);
        if (r < 0)
                return log_error_errno(r, "bpf-unix-socket-protocol: Failed to pin BPF maps: %m");

        r = unix_socket_protocol_bpf__attach(obj);
        if (r < 0)
                return log_error_errno(r, "bpf-unix-socket-protocol: Failed to attach BPF object: %m");

        return 0;
}

static int unix_socket_protocol_bpf_try(bool use_new_removexattr, struct unix_socket_protocol_bpf **ret) {
        _cleanup_(unix_socket_protocol_bpf_destroyp) struct unix_socket_protocol_bpf *obj = NULL;
        int r;

        obj = unix_socket_protocol_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-unix-socket-protocol: Failed to open BPF object: %m");

        r = sym_bpf_program__set_autoload(
                        use_new_removexattr
                                ? obj->progs.unix_socket_protocol_inode_removexattr___old
                                : obj->progs.unix_socket_protocol_inode_removexattr___new,
                        false);
        if (r < 0)
                return log_error_errno(r, "bpf-unix-socket-protocol: Failed to disable program variant: %m");

        r = unix_socket_protocol_bpf_prepare(obj);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(obj);
        return 0;
}

int unix_socket_protocol_bpf_new(struct unix_socket_protocol_bpf **ret) {
        int r;

        assert(ret);

        /* Try new inode_removexattr signature (with mnt_idmap) first, fall back to old */
        r = unix_socket_protocol_bpf_try(/* use_new_removexattr= */ true, ret);
        if (r >= 0) {
                log_info("bpf-unix-socket-protocol: BPF programs attached");
                return 0;
        }

        log_debug("bpf-unix-socket-protocol: Trying compat inode_removexattr variant.");

        r = unix_socket_protocol_bpf_try(/* use_new_removexattr= */ false, ret);
        if (r < 0)
                return r;

        log_info("bpf-unix-socket-protocol: BPF programs attached (compat)");
        return 0;
}

#else /* ! BPF_FRAMEWORK */
int unix_socket_protocol_bpf_supported(void) {
        return false;
}

struct unix_socket_protocol_bpf* unix_socket_protocol_bpf_destroy(struct unix_socket_protocol_bpf *obj) {
        return NULL;
}

int unix_socket_protocol_bpf_new(struct unix_socket_protocol_bpf **ret) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                    "bpf-unix-socket-protocol: Failed to install; BPF framework is not supported");
}
#endif
