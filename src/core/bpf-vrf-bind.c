/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-netlink.h"

#include "alloc-util.h"
#include "bpf-vrf-bind.h"
#include "cgroup.h"
#include "fd-util.h"
#include "netlink-util.h"
#include "string-util.h"
#include "unit.h"

#if BPF_FRAMEWORK
/* libbpf, clang, llvm and bpftool compile time dependencies are satisfied */
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/vrf-bind/vrf-bind-skel.h"

static struct vrf_bind_bpf *vrf_bind_bpf_free(struct vrf_bind_bpf *obj) {
        vrf_bind_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct vrf_bind_bpf *, vrf_bind_bpf_free);

int bpf_vrf_bind_supported(void) {
        _cleanup_(vrf_bind_bpf_freep) struct vrf_bind_bpf *obj = NULL;
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        if (dlopen_bpf_full(LOG_WARNING) < 0)
                return (supported = false);

        obj = vrf_bind_bpf__open();
        if (!obj) {
                log_debug_errno(errno, "bpf-vrf-bind: Failed to open BPF object: %m");
                return (supported = false);
        }

        r = vrf_bind_bpf__load(obj);
        if (r != 0) {
                log_debug_errno(r, "bpf-vrf-bind: Failed to load BPF object: %m");
                return (supported = false);
        }

        return (supported = bpf_can_link_program(obj->progs.sd_bind_vrf));
}

static int vrf_bind_install_impl(Unit *u) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        _cleanup_(vrf_bind_bpf_freep) struct vrf_bind_bpf *obj = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_free_ char *cgroup_path = NULL;
        _cleanup_close_ int cgroup_fd = -EBADF;
        CGroupContext *cc;
        CGroupRuntime *crt;
        int r, ifindex;

        assert(u);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        r = cg_get_path(crt->cgroup_path, /* suffix = */ NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-vrf-bind: Failed to get cgroup path: %m");

        if (isempty(cc->vrf_bind_interface))
                return 0;

        ifindex = rtnl_resolve_interface(&rtnl, cc->vrf_bind_interface);
        if (ifindex < 0) {
                log_unit_warning_errno(u, ifindex,
                                       "bpf-vrf-bind: Couldn't find index of network interface '%s', ignoring: %m",
                                       cc->vrf_bind_interface);
                return 0;
        }
        log_unit_debug(u, "bpf-vrf-bind: Found index %d for network interface '%s'", ifindex, cc->vrf_bind_interface);

        /* Open the BPF skeleton */
        obj = vrf_bind_bpf__open();
        if (!obj)
                return log_unit_error_errno(u, errno, "bpf-vrf-bind: Failed to open BPF object: %m");

        /* Set the VRF interface index in rodata before loading */
        obj->rodata->vrf_ifindex = ifindex;

        /* Load the BPF program */
        r = vrf_bind_bpf__load(obj);
        if (r != 0)
                return log_unit_error_errno(u, r, "bpf-vrf-bind: Failed to load BPF object: %m");

        /* Open the cgroup directory */
        cgroup_fd = open(cgroup_path, O_PATH | O_CLOEXEC | O_DIRECTORY, 0);
        if (cgroup_fd < 0)
                return log_unit_error_errno(u, errno, "bpf-vrf-bind: Failed to open cgroup directory '%s': %m", cgroup_path);

        /* Attach the BPF program to the cgroup */
        link = sym_bpf_program__attach_cgroup(obj->progs.sd_bind_vrf, cgroup_fd);
        r = bpf_get_error_translated(link);
        if (r != 0)
                return log_unit_error_errno(u, r, "bpf-vrf-bind: Failed to create cgroup link: %m");

        /* Store the link in CGroupRuntime */
        crt->bpf_vrf_bind_link = TAKE_PTR(link);

        log_unit_debug(u, "bpf-vrf-bind: Successfully installed VRF binding for interface '%s' (ifindex=%d)",
                       cc->vrf_bind_interface, ifindex);

        return 0;
}

int bpf_vrf_bind_install(Unit *u) {
        CGroupRuntime *crt;
        int r;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        r = vrf_bind_install_impl(u);
        return r;
}

int bpf_vrf_bind_serialize(Unit *u, FILE *f, FDSet *fds) {
        CGroupRuntime *crt;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        return bpf_serialize_link(f, fds, "bpf-vrf-bind-fd", crt->bpf_vrf_bind_link);
}

#else /* ! BPF_FRAMEWORK */
int bpf_vrf_bind_supported(void) {
        return 0;
}

int bpf_vrf_bind_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                    "bpf-vrf-bind: Failed to install; BPF framework is not supported");
}

int bpf_vrf_bind_serialize(Unit *u, FILE *f, FDSet *fds) {
        return 0;
}
#endif
