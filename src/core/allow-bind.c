/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBBPF
#include <bpf/bpf.h>
#endif

#include "allow-bind.h"
#include "fd-util.h"
#include "unit.h"

#if BPF_FRAMEWORK
/* libbpf, clang and llc compile time dependencies are satisfied */
#include "bpf/allow_bind/allow-bind-skel.h"

static struct allow_bind_bpf *allow_bind_bpf_free(struct allow_bind_bpf *obj) {
        if (obj && libbpf_get_error(obj) == 0)
                (void) allow_bind_bpf__destroy(obj);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct allow_bind_bpf *, allow_bind_bpf_free);

static int can_link_bpf_program(struct bpf_program *prog) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        int err;

        assert(prog);

        link = bpf_program__attach_cgroup(prog, -1);
        if (!link)
                return -ENOMEM;

        err = libbpf_get_error(link);
        if (err != -EINVAL && err != -EBADF)
                return err;

        /* EBADF indicates that bpf_link is supported by kernel. */
        return err == -EBADF;
}

static int prepare_allow_bind_bpf(Unit *u, const Set *ports_v6, const Set *ports_v4, struct allow_bind_bpf **ret_obj) {
        _cleanup_(allow_bind_bpf_freep) struct allow_bind_bpf *obj = 0;
        int map_fd, r = 0;
        uint8_t dummy;
        void *port;

        obj = allow_bind_bpf__open();
        if (!obj)
                return log_unit_error_errno(u, r, "Failed to open BPF object");

        r = bpf_map__resize(obj->maps.ports_v6, MAX(set_size(ports_v6), 1u));
        if (r)
                return log_unit_error_errno(u, r,
                                "Failed to resize BPF map '%s': %m",
                                bpf_map__name(obj->maps.ports_v6));

        r = bpf_map__resize(obj->maps.ports_v4, MAX(set_size(ports_v4), 1u));
        if (r)
                return log_unit_error_errno(u, r,
                                "Failed to resize BPF map '%s': %m",
                                bpf_map__name(obj->maps.ports_v4));

        r = allow_bind_bpf__load(obj);
        if (r)
                return log_unit_error_errno(u, r, "Failed to load BPF object");

        map_fd = bpf_map__fd(obj->maps.ports_v6);
        if (map_fd < 0)
                return log_unit_error_errno(u, map_fd, "Failed to get BPF map fd");

        SET_FOREACH(port, ports_v6)
                if (bpf_map_update_elem(map_fd, &port, &dummy, BPF_ANY))
                        return log_unit_error_errno(u, -1, "Failed to update BPF map");

        map_fd = bpf_map__fd(obj->maps.ports_v4);
        if (map_fd < 0)
                return log_unit_error_errno(u, map_fd, "Failed to get BPF map fd");

        SET_FOREACH(port, ports_v4)
                if (bpf_map_update_elem(map_fd, &port, &dummy, BPF_ANY))
                        return log_unit_error_errno(u, -1, "Failed to update BPF map");

        *ret_obj = TAKE_PTR(obj);
        return 0;
}

int allow_bind_supported(void) {
        _cleanup_(allow_bind_bpf_freep) struct allow_bind_bpf *obj = NULL;

        int r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "Can't determine whether the unified hierarchy is used: %m");

        if (r == 0) {
                log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "Not running with unified cgroup hierarchy, BPF is not supported");
                return 0;
        }

        if (!bpf_probe_prog_type(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, /*ifindex=*/0)) {
                log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "BPF program type cgroup_sock_addr is not supported");
                return 0;
        }

        r = prepare_allow_bind_bpf(NULL, NULL, NULL, &obj);
        if (r < 0)
                return log_debug_errno(r, "Failed to load BPF object: %m");

        return can_link_bpf_program(obj->progs.allow_bind_v6);
}

int allow_bind_install(Unit *u) {
        _cleanup_(bpf_link_freep) struct bpf_link *ipv4 = NULL, *ipv6 = NULL;
        _cleanup_(allow_bind_bpf_freep) struct allow_bind_bpf *obj = NULL;
        _cleanup_free_ char *cgroup_path = NULL;
        _cleanup_close_ int cgroup_fd = -1;
        CGroupContext *cc;
        int r;

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to get cgroup path: %m");

        if (!cc->allow_bind_ports)
                return 0;

        r = prepare_allow_bind_bpf(u, cc->allow_bind_ports, cc->allow_bind_ports, &obj);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to load BPF object: %m");

        cgroup_fd = open(cgroup_path, O_RDONLY | O_CLOEXEC, 0);
        if (cgroup_fd < 0)
                return -errno;

        ipv4 = bpf_program__attach_cgroup(obj->progs.allow_bind_v4, cgroup_fd);
        if (libbpf_get_error(ipv4))
                return log_unit_error_errno(u, r, "Failed to create ipv4 cgroup link");

        ipv6 = bpf_program__attach_cgroup(obj->progs.allow_bind_v6, cgroup_fd);
        if (libbpf_get_error(ipv6))
                return log_unit_error_errno(u, r, "Failed to create ipv6 cgroup link");

        u->ipv4_allow_bind_bpf_link = TAKE_PTR(ipv4);
        u->ipv6_allow_bind_bpf_link = TAKE_PTR(ipv6);

        return 0;
}
#else /* ! BPF_FRAMEWORK */
int allow_bind_supported(void) {
        return 0;
}

int allow_bind_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "Failed to install AllowBind: BPF programs built from source code are not supported: %m");
}

#endif
