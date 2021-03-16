/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBBPF
#include <bpf/bpf.h>
#endif

#include "socket-bind.h"
#include "fd-util.h"
#include "unit.h"

#if BPF_FRAMEWORK
/* libbpf, clang, llvm and bpftool compile time dependencies are satisfied */
#include "bpf/socket_bind/socket-bind.skel.h"
#include "bpf/socket_bind/socket-bind-api.bpf.h"

static struct socket_bind_bpf *socket_bind_bpf_free(struct socket_bind_bpf *obj) {
        /* socket_bind_bpf__destroy handles object == NULL case */
        (void) socket_bind_bpf__destroy(obj);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct socket_bind_bpf *, socket_bind_bpf_free);

static int update_rules_map(
                int map_fd, CGroupSocketBindItem *head, enum socket_bind_action action, uint32_t* index) {
        CGroupSocketBindItem *item;

        assert(map_fd >= 0);
        assert(index);

        LIST_FOREACH(socket_bind_items, item, head) {
                const uint32_t key = (*index)++;
                struct socket_bind_rule val = {
                        .address_family = (uint32_t) item->address_family,
                        .nr_ports = item->nr_ports,
                        .port_min = item->port_min,
                        .action = action,
                };

                if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0)
                        return -errno;
        }

        return 0;
}

static int prepare_socket_bind_bpf(
                Unit *u, CGroupSocketBindItem *allow, CGroupSocketBindItem *deny, struct socket_bind_bpf **ret_obj) {
        _cleanup_(socket_bind_bpf_freep) struct socket_bind_bpf *obj = 0;
        uint32_t rule_count = 0, index = 0;
        CGroupSocketBindItem *item;
        int map_fd, r;

        assert(ret_obj);

        LIST_FOREACH(socket_bind_items, item,  allow)
                rule_count += 1;

        LIST_FOREACH(socket_bind_items, item, deny)
                rule_count += 1;

        if (rule_count > socket_bind_max_rules)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(EINVAL),
                                "Maximum number of socket bind rules=%u is exceeded", socket_bind_max_rules);

        obj = socket_bind_bpf__open();
        if (!obj)
                return log_unit_error_errno(u, SYNTHETIC_ERRNO(ENOMEM), "Failed to open BPF object");

        if (bpf_map__resize(obj->maps.rules, MAX(rule_count, 1u)) != 0)
                return log_unit_error_errno(u, errno,
                                "Failed to resize BPF map '%s': %m", bpf_map__name(obj->maps.rules));

        if (socket_bind_bpf__load(obj) != 0)
                return log_unit_error_errno(u, errno, "Failed to load BPF object");

        map_fd = bpf_map__fd(obj->maps.rules);
        assert(map_fd >= 0);

        r = update_rules_map(map_fd, allow, SOCKET_BIND_ALLOW, &index);
        if (r < 0)
                return log_unit_error_errno(
                                u, r, "Failed to put socket bind allow rules into BPF map '%s'",
                                bpf_map__name(obj->maps.rules));

        r = update_rules_map(map_fd, deny, SOCKET_BIND_DENY, &index);
        if (r < 0)
                return log_unit_error_errno(
                                u, r, "Failed to put socket bind deny rules into BPF map '%s'",
                                bpf_map__name(obj->maps.rules));

        *ret_obj = TAKE_PTR(obj);
        return 0;
}

int socket_bind_supported(void) {
        _cleanup_(socket_bind_bpf_freep) struct socket_bind_bpf *obj = NULL;

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

        r = prepare_socket_bind_bpf(/*unit=*/NULL, /*allow_rules=*/NULL, /*deny_rules=*/NULL, &obj);
        if (r < 0) {
                log_debug_errno(r, "BPF based socket_bind is not supported: %m");
                return 0;
        }

        return can_link_bpf_program(obj->progs.socket_bind_v6);
}

static int socket_bind_install_impl(Unit *u) {
        _cleanup_(bpf_link_freep) struct bpf_link *ipv4 = NULL, *ipv6 = NULL;
        _cleanup_(socket_bind_bpf_freep) struct socket_bind_bpf *obj = NULL;
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

        if (!cc->socket_bind_allow && !cc->socket_bind_deny)
                return 0;

        r = prepare_socket_bind_bpf(u, cc->socket_bind_allow, cc->socket_bind_deny, &obj);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to load BPF object: %m");

        cgroup_fd = open(cgroup_path, O_RDONLY | O_CLOEXEC, 0);
        if (cgroup_fd < 0)
                return log_unit_error_errno(
                                u, errno, "Failed to open cgroup=%s for read", cgroup_path);

        ipv4 = bpf_program__attach_cgroup(obj->progs.socket_bind_v4, cgroup_fd);
        r = libbpf_get_error(ipv4);
        if (r != 0)
                return log_unit_error_errno(u, r, "Failed to link '%s' cgroup-bpf program ",
                                bpf_program__name(obj->progs.socket_bind_v4));

        ipv6 = bpf_program__attach_cgroup(obj->progs.socket_bind_v6, cgroup_fd);
        r = libbpf_get_error(ipv6);
        if (r != 0)
                return log_unit_error_errno(u, r, "Failed to link '%s' cgroup-bpf program ",
                                bpf_program__name(obj->progs.socket_bind_v6));

        u->ipv4_socket_bind_bpf_link = TAKE_PTR(ipv4);
        u->ipv6_socket_bind_bpf_link = TAKE_PTR(ipv6);

        return 0;
}

int socket_bind_install(Unit *u) {
        int r = socket_bind_install_impl(u);
        if (r == -ENOMEM)
                return r;

        fdset_close(u->socket_bind_restored_fds);
        return r;
}

#else /* ! BPF_FRAMEWORK */
int socket_bind_supported(void) {
        return 0;
}

int socket_bind_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "Failed to install AllowBind: BPF programs built from source code are not supported: %m");
}

#endif
int socket_bind_restore(Unit *u, int fd) {
        int r;

        assert(u);

        if (!u->socket_bind_restored_fds) {
                u->socket_bind_restored_fds = fdset_new();
                if (!u->socket_bind_restored_fds)
                        return log_oom();
        }

        r = fdset_put(u->socket_bind_restored_fds, fd);
        if (r < 0)
                return log_unit_debug(u, "Failed to put socket-bind BPF link fd %d to restored fdset", fd);

        return 0;
}
