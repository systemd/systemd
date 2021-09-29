/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if BPF_FRAMEWORK
#include <bpf/bpf.h>
#endif

#include "fd-util.h"
#include "bpf-socket-bind.h"

#if BPF_FRAMEWORK
/* libbpf, clang, llvm and bpftool compile time dependencies are satisfied */
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/socket_bind/socket-bind.skel.h"
#include "bpf/socket_bind/socket-bind-api.bpf.h"

static struct socket_bind_bpf *socket_bind_bpf_free(struct socket_bind_bpf *obj) {
        /* socket_bind_bpf__destroy handles object == NULL case */
        (void) socket_bind_bpf__destroy(obj);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct socket_bind_bpf *, socket_bind_bpf_free);

static int update_rules_map(
                int map_fd,
                CGroupSocketBindItem *head) {

        CGroupSocketBindItem *item;
        uint32_t i = 0;

        assert(map_fd >= 0);

        LIST_FOREACH(socket_bind_items, item, head) {
                struct socket_bind_rule val = {
                        .address_family = (uint32_t) item->address_family,
                        .protocol = item->ip_protocol,
                        .nr_ports = item->nr_ports,
                        .port_min = item->port_min,
                };

                uint32_t key = i++;

                if (sym_bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0)
                        return -errno;
        }

        return 0;
}

static int prepare_socket_bind_bpf(
                Unit *u,
                CGroupSocketBindItem *allow,
                CGroupSocketBindItem *deny,
                struct socket_bind_bpf **ret_obj) {

        _cleanup_(socket_bind_bpf_freep) struct socket_bind_bpf *obj = NULL;
        size_t allow_count = 0, deny_count = 0;
        int allow_map_fd, deny_map_fd, r;
        CGroupSocketBindItem *item;

        assert(ret_obj);

        LIST_FOREACH(socket_bind_items, item, allow)
                allow_count++;

        LIST_FOREACH(socket_bind_items, item, deny)
                deny_count++;

        if (allow_count > SOCKET_BIND_MAX_RULES)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, SYNTHETIC_ERRNO(EINVAL),
                                           "Maximum number of socket bind rules=%u is exceeded", SOCKET_BIND_MAX_RULES);

        if (deny_count > SOCKET_BIND_MAX_RULES)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, SYNTHETIC_ERRNO(EINVAL),
                                           "Maximum number of socket bind rules=%u is exceeded", SOCKET_BIND_MAX_RULES);

        obj = socket_bind_bpf__open();
        if (!obj)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_DEBUG, SYNTHETIC_ERRNO(ENOMEM),
                                           "Failed to open BPF object");

        if (sym_bpf_map__resize(obj->maps.sd_bind_allow, MAX(allow_count, 1u)) != 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, errno,
                                           "Failed to resize BPF map '%s': %m", sym_bpf_map__name(obj->maps.sd_bind_allow));

        if (sym_bpf_map__resize(obj->maps.sd_bind_deny, MAX(deny_count, 1u)) != 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, errno,
                                           "Failed to resize BPF map '%s': %m", sym_bpf_map__name(obj->maps.sd_bind_deny));

        if (socket_bind_bpf__load(obj) != 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_DEBUG, errno,
                                           "Failed to load BPF object: %m");

        allow_map_fd = sym_bpf_map__fd(obj->maps.sd_bind_allow);
        assert(allow_map_fd >= 0);

        r = update_rules_map(allow_map_fd, allow);
        if (r < 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, r,
                                           "Failed to put socket bind allow rules into BPF map '%s'",
                                           sym_bpf_map__name(obj->maps.sd_bind_allow));

        deny_map_fd = sym_bpf_map__fd(obj->maps.sd_bind_deny);
        assert(deny_map_fd >= 0);

        r = update_rules_map(deny_map_fd, deny);
        if (r < 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, r,
                                           "Failed to put socket bind deny rules into BPF map '%s'",
                                           sym_bpf_map__name(obj->maps.sd_bind_deny));

        *ret_obj = TAKE_PTR(obj);
        return 0;
}

int bpf_socket_bind_supported(void) {
        _cleanup_(socket_bind_bpf_freep) struct socket_bind_bpf *obj = NULL;
        int r;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_debug_errno(r, "Can't determine whether the unified hierarchy is used: %m");
        if (r == 0) {
                log_debug("Not running with unified cgroup hierarchy, BPF is not supported");
                return false;
        }

        if (dlopen_bpf() < 0)
                return false;

        if (!sym_bpf_probe_prog_type(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, /*ifindex=*/0)) {
                log_debug("BPF program type cgroup_sock_addr is not supported");
                return false;
        }

        r = prepare_socket_bind_bpf(/*unit=*/NULL, /*allow_rules=*/NULL, /*deny_rules=*/NULL, &obj);
        if (r < 0) {
                log_debug_errno(r, "BPF based socket_bind is not supported: %m");
                return false;
        }

        return bpf_can_link_program(obj->progs.sd_bind4);
}

int bpf_socket_bind_add_initial_link_fd(Unit *u, int fd) {
        int r;

        assert(u);

        if (!u->initial_socket_bind_link_fds) {
                u->initial_socket_bind_link_fds = fdset_new();
                if (!u->initial_socket_bind_link_fds)
                        return log_oom();
        }

        r = fdset_put(u->initial_socket_bind_link_fds, fd);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to put socket-bind BPF link fd %d to initial fdset", fd);

        return 0;
}

static int socket_bind_install_impl(Unit *u) {
        _cleanup_(bpf_link_freep) struct bpf_link *ipv4 = NULL, *ipv6 = NULL;
        _cleanup_(socket_bind_bpf_freep) struct socket_bind_bpf *obj = NULL;
        _cleanup_free_ char *cgroup_path = NULL;
        _cleanup_close_ int cgroup_fd = -1;
        CGroupContext *cc;
        int r;

        assert(u);

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
                return log_unit_error_errno(u, errno, "Failed to open cgroup=%s for reading: %m", cgroup_path);

        ipv4 = sym_bpf_program__attach_cgroup(obj->progs.sd_bind4, cgroup_fd);
        r = sym_libbpf_get_error(ipv4);
        if (r != 0)
                return log_unit_error_errno(u, r, "Failed to link '%s' cgroup-bpf program: %m",
                                            sym_bpf_program__name(obj->progs.sd_bind4));

        ipv6 = sym_bpf_program__attach_cgroup(obj->progs.sd_bind6, cgroup_fd);
        r = sym_libbpf_get_error(ipv6);
        if (r != 0)
                return log_unit_error_errno(u, r, "Failed to link '%s' cgroup-bpf program: %m",
                                            sym_bpf_program__name(obj->progs.sd_bind6));

        u->ipv4_socket_bind_link = TAKE_PTR(ipv4);
        u->ipv6_socket_bind_link = TAKE_PTR(ipv6);

        return 0;
}

int bpf_socket_bind_install(Unit *u) {
        int r;

        assert(u);

        r = socket_bind_install_impl(u);
        if (r == -ENOMEM)
                return r;

        fdset_close(u->initial_socket_bind_link_fds);
        return r;
}

int bpf_serialize_socket_bind(Unit *u, FILE *f, FDSet *fds) {
        int r;

        assert(u);

        r = bpf_serialize_link(f, fds, "ipv4-socket-bind-bpf-link", u->ipv4_socket_bind_link);
        if (r < 0)
                return r;

        return bpf_serialize_link(f, fds, "ipv6-socket-bind-bpf-link", u->ipv6_socket_bind_link);
}

#else /* ! BPF_FRAMEWORK */
int bpf_socket_bind_supported(void) {
        return false;
}

int bpf_socket_bind_add_initial_link_fd(Unit *u, int fd) {
        return 0;
}

int bpf_socket_bind_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP), "Failed to install socket bind: BPF framework is not supported");
}

int bpf_serialize_socket_bind(Unit *u, FILE *f, FDSet *fds) {
        return 0;
}
#endif
