/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "bpf-restrict-ifaces.h"
#include "netlink-util.h"

#if BPF_FRAMEWORK
/* libbpf, clang and llc compile time dependencies are satisfied */

#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf-util.h"
#include "bpf/restrict_ifaces/restrict-ifaces-skel.h"

static struct restrict_ifaces_bpf *restrict_ifaces_bpf_free(struct restrict_ifaces_bpf *obj) {
        restrict_ifaces_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct restrict_ifaces_bpf *, restrict_ifaces_bpf_free);

static int prepare_restrict_ifaces_bpf(
                Unit* u,
                bool is_allow_list,
                const Set *restrict_network_interfaces,
                struct restrict_ifaces_bpf **ret_object) {

        _cleanup_(restrict_ifaces_bpf_freep) struct restrict_ifaces_bpf *obj = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        char *iface;
        int r, map_fd;

        assert(ret_object);

        obj = restrict_ifaces_bpf__open();
        if (!obj)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_DEBUG, errno, "restrict-interfaces: Failed to open BPF object: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.sd_restrictif, MAX(set_size(restrict_network_interfaces), 1u));
        if (r != 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, r,
                                "restrict-interfaces: Failed to resize BPF map '%s': %m",
                                sym_bpf_map__name(obj->maps.sd_restrictif));

        obj->rodata->is_allow_list = is_allow_list;

        r = restrict_ifaces_bpf__load(obj);
        if (r != 0)
                return log_unit_full_errno(u, u ? LOG_ERR : LOG_DEBUG, r, "restrict-interfaces: Failed to load BPF object: %m");

        map_fd = sym_bpf_map__fd(obj->maps.sd_restrictif);

        SET_FOREACH(iface, restrict_network_interfaces) {
                uint8_t dummy = 0;
                int ifindex;

                ifindex = rtnl_resolve_interface(&rtnl, iface);
                if (ifindex < 0) {
                        log_unit_warning_errno(u, ifindex,
                                               "restrict-interfaces: Couldn't find index of network interface '%s', ignoring: %m",
                                               iface);
                        continue;
                }

                if (sym_bpf_map_update_elem(map_fd, &ifindex, &dummy, BPF_ANY))
                        return log_unit_full_errno(u, u ? LOG_ERR : LOG_WARNING, errno,
                                                   "restrict-interfaces: Failed to update BPF map '%s' fd: %m",
                                                   sym_bpf_map__name(obj->maps.sd_restrictif));
        }

        *ret_object = TAKE_PTR(obj);
        return 0;
}

int bpf_restrict_ifaces_supported(void) {
        _cleanup_(restrict_ifaces_bpf_freep) struct restrict_ifaces_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        if (!cgroup_bpf_supported())
                return (supported = false);

        if (!compat_libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_CGROUP_SKB, /*opts=*/NULL)) {
                log_debug("restrict-interfaces: BPF program type cgroup_skb is not supported");
                return (supported = false);
        }

        r = prepare_restrict_ifaces_bpf(NULL, true, NULL, &obj);
        if (r < 0) {
                log_debug_errno(r, "restrict-interfaces: Failed to load BPF object: %m");
                return (supported = false);
        }

        return (supported = bpf_can_link_program(obj->progs.sd_restrictif_i));
}

static int restrict_ifaces_install_impl(Unit *u) {
        _cleanup_(bpf_link_freep) struct bpf_link *egress_link = NULL, *ingress_link = NULL;
        _cleanup_(restrict_ifaces_bpf_freep) struct restrict_ifaces_bpf *obj = NULL;
        _cleanup_free_ char *cgroup_path = NULL;
        _cleanup_close_ int cgroup_fd = -EBADF;
        CGroupContext *cc;
        CGroupRuntime *crt;
        int r;

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, crt->cgroup_path, NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "restrict-interfaces: Failed to get cgroup path: %m");

        if (!cc->restrict_network_interfaces)
                return 0;

        r = prepare_restrict_ifaces_bpf(u,
                cc->restrict_network_interfaces_is_allow_list,
                cc->restrict_network_interfaces,
                &obj);
        if (r < 0)
                return r;

        cgroup_fd = open(cgroup_path, O_PATH | O_CLOEXEC | O_DIRECTORY, 0);
        if (cgroup_fd < 0)
                return -errno;

        ingress_link = sym_bpf_program__attach_cgroup(obj->progs.sd_restrictif_i, cgroup_fd);
        r = bpf_get_error_translated(ingress_link);
        if (r != 0)
                return log_unit_error_errno(u, r, "restrict-interfaces: Failed to create ingress cgroup link: %m");

        egress_link = sym_bpf_program__attach_cgroup(obj->progs.sd_restrictif_e, cgroup_fd);
        r = bpf_get_error_translated(egress_link);
        if (r != 0)
                return log_unit_error_errno(u, r, "restrict-interfaces: Failed to create egress cgroup link: %m");

        crt->restrict_ifaces_ingress_bpf_link = TAKE_PTR(ingress_link);
        crt->restrict_ifaces_egress_bpf_link = TAKE_PTR(egress_link);

        return 0;
}

int bpf_restrict_ifaces_install(Unit *u) {
        CGroupRuntime *crt;
        int r;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        r = restrict_ifaces_install_impl(u);
        fdset_close(crt->initial_restrict_ifaces_link_fds, /* async= */ false);
        return r;
}

int bpf_restrict_ifaces_serialize(Unit *u, FILE *f, FDSet *fds) {
        CGroupRuntime *crt;
        int r;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        r = bpf_serialize_link(f, fds, "restrict-ifaces-bpf-fd", crt->restrict_ifaces_ingress_bpf_link);
        if (r < 0)
                return r;

        return bpf_serialize_link(f, fds, "restrict-ifaces-bpf-fd", crt->restrict_ifaces_egress_bpf_link);
}

int bpf_restrict_ifaces_add_initial_link_fd(Unit *u, int fd) {
        int r;

        assert(u);

        CGroupRuntime *crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return -EINVAL;

        if (!crt->initial_restrict_ifaces_link_fds) {
                crt->initial_restrict_ifaces_link_fds = fdset_new();
                if (!crt->initial_restrict_ifaces_link_fds)
                        return log_oom();
        }

        r = fdset_put(crt->initial_restrict_ifaces_link_fds, fd);
        if (r < 0)
                return log_unit_error_errno(u, r,
                        "restrict-interfaces: Failed to put restrict-ifaces-bpf-fd %d to restored fdset: %m", fd);

        return 0;
}

#else /* ! BPF_FRAMEWORK */
int bpf_restrict_ifaces_supported(void) {
        return 0;
}

int bpf_restrict_ifaces_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "restrict-interfaces: Failed to install; BPF programs built from source code are not supported: %m");
}

int bpf_restrict_ifaces_serialize(Unit *u, FILE *f, FDSet *fds) {
        return 0;
}

int bpf_restrict_ifaces_add_initial_link_fd(Unit *u, int fd) {
        return 0;
}
#endif
