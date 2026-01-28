/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "bpf-bind-iface.h"
#include "cgroup.h"
#include "fd-util.h"
#include "netlink-util.h"
#include "string-util.h"
#include "unit.h"

#if BPF_FRAMEWORK
/* libbpf, clang, llvm and bpftool compile time dependencies are satisfied */
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/bind-iface/bind-iface-skel.h"

static struct bind_iface_bpf *bind_iface_bpf_free(struct bind_iface_bpf *obj) {
        bind_iface_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct bind_iface_bpf *, bind_iface_bpf_free);

int bpf_bind_network_interface_supported(void) {
        _cleanup_(bind_iface_bpf_freep) struct bind_iface_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        if (dlopen_bpf_full(LOG_WARNING) < 0)
                return (supported = false);

        obj = bind_iface_bpf__open();
        if (!obj) {
                log_debug_errno(errno, "bind-interface: Failed to open BPF object: %m");
                return (supported = false);
        }

        r = bind_iface_bpf__load(obj);
        if (r != 0) {
                log_debug_errno(r, "bind-interface: Failed to load BPF object: %m");
                return (supported = false);
        }

        return (supported = bpf_can_link_program(obj->progs.sd_bind_interface));
}

static int bind_network_interface_install_impl(Unit *u, CGroupRuntime *crt) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        _cleanup_(bind_iface_bpf_freep) struct bind_iface_bpf *obj = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ char *cgroup_path = NULL;
        _cleanup_close_ int cgroup_fd = -EBADF;
        int r, ifindex;

        assert(u);
        assert(crt);

        CGroupContext *cc = ASSERT_PTR(unit_get_cgroup_context(u));

        if (isempty(cc->bind_network_interface))
                return 0;

        r = cg_get_path(crt->cgroup_path, /* suffix= */ NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "bind-interface: Failed to get cgroup path: %m");

        ifindex = rtnl_resolve_interface(&rtnl, cc->bind_network_interface);
        if (ifindex < 0) {
                log_unit_warning_errno(u, ifindex,
                                       "bind-interface: Couldn't find index of network interface '%s', ignoring: %m",
                                       cc->bind_network_interface);
                return 0;
        }
        log_unit_debug(u, "bind-interface: Found index %d for network interface '%s'", ifindex, cc->bind_network_interface);

        /* Open the BPF skeleton */
        obj = bind_iface_bpf__open();
        if (!obj)
                return log_unit_error_errno(u, errno, "bind-interface: Failed to open BPF object: %m");

        /* Set the VRF interface index in rodata before loading */
        obj->rodata->ifindex = ifindex;

        /* Load the BPF program */
        r = bind_iface_bpf__load(obj);
        if (r != 0)
                return log_unit_error_errno(u, r, "bind-interface: Failed to load BPF object: %m");

        /* Open the cgroup directory */
        cgroup_fd = open(cgroup_path, O_PATH | O_CLOEXEC | O_DIRECTORY, 0);
        if (cgroup_fd < 0)
                return log_unit_error_errno(u, errno, "bind-interface: Failed to open cgroup directory '%s': %m", cgroup_path);

        /* Attach the BPF program to the cgroup */
        link = sym_bpf_program__attach_cgroup(obj->progs.sd_bind_interface, cgroup_fd);
        r = bpf_get_error_translated(link);
        if (r != 0)
                return log_unit_error_errno(u, r, "bind-interface: Failed to create cgroup link: %m");

        /* Store the link in CGroupRuntime */
        crt->bpf_bind_network_interface_link = TAKE_PTR(link);

        log_unit_debug(u, "bind-interface: Successfully installed VRF binding for interface '%s' (ifindex=%d)",
                       cc->bind_network_interface, ifindex);

        return 0;
}

int bpf_bind_network_interface_install(Unit *u) {
        CGroupRuntime *crt;
        int r;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        r = bind_network_interface_install_impl(u, crt);
        crt->initial_bind_network_interface_link_fd = safe_close(crt->initial_bind_network_interface_link_fd);
        return r;
}

int bpf_bind_network_interface_serialize(Unit *u, FILE *f, FDSet *fds) {
        CGroupRuntime *crt;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        return bpf_serialize_link(f, fds, "bind-iface-bpf-fd", crt->bpf_bind_network_interface_link);
}

#else /* ! BPF_FRAMEWORK */
int bpf_bind_network_interface_supported(void) {
        return 0;
}

int bpf_bind_network_interface_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                    "bind-interface: Failed to install; BPF framework is not supported");
}

int bpf_bind_network_interface_serialize(Unit *u, FILE *f, FDSet *fds) {
        return 0;
}
#endif
