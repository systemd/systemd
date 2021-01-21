/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "architecture.h"
#include "cgroup-bpf.h"
#include "restrict-ifaces.h"
#include "set.h"
#include "unit.h"

#if BUILD_BPF
/* libbpf, clang and llc compile time dependencies are satisfied */

#include "bpf-object.h"
#include "bpf/restrict_ifaces/restrict-ifaces-hexdump.h"

static int prepare_bpf_object(Unit* u, bool is_allow_list,
                const Set *restrict_network_interfaces,
                struct bpf_object **ret_object) {
        _cleanup_(bpf_object_freep) struct bpf_object *object = NULL;
        const char *map_name = "ifaces_map";
        char *iface;
        int map_fd, r, bss_map_fd;
        uint8_t dummy = 0;
        uint32_t ifindex, zero=0;
        uint8_t is_allow_list_u8 = (uint8_t) is_allow_list;

        assert(restrict_network_interfaces);
        assert(ret_object);

        /* pass a short name to avoid trimming part of the name */
        r = bpf_object_new(restrict_ifaces_hexdump_buffer,
                sizeof(restrict_ifaces_hexdump_buffer), "rifaces", &object);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to create BPF object from hexdump buffer: %m");

        r = bpf_object_resize_map(object, map_name, set_size(restrict_network_interfaces));
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to resize BPF map '%s': %m", map_name);

        r = bpf_object_load(object);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to load BPF object: %m");

        /* set value of is_allow_list global variable */
        bss_map_fd = bpf_object_get_map_fd(object, "rifaces.data");
        if (bss_map_fd < 0)
                return log_unit_error_errno(u, r, "Failed to find bss map: %m");

        r = bpf_map_update_elem(bss_map_fd, &zero, &is_allow_list_u8, BPF_ANY);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to update bss map: %m");

        map_fd = bpf_object_get_map_fd(object, map_name);
        if (map_fd < 0)
                return log_unit_error_errno(u, r, "Failed to get BPF map '%s' fd: %m", map_name);

        SET_FOREACH(iface, restrict_network_interfaces) {
                ifindex = if_nametoindex(iface);
                if (ifindex == 0) {
                        log_unit_warning(u, "Could't find index of network interface, ignoring '%s'", iface);
                        continue;
                }

                r = bpf_map_update_elem(map_fd, &ifindex, &dummy, BPF_ANY);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to update BPF map '%s' fd: %m", map_name);
        }

        *ret_object = TAKE_PTR(object);

        return 0;
}

int restrict_network_interfaces_supported(void) {
       _cleanup_(bpf_object_freep) struct bpf_object *obj = NULL;
        int arch, r;
        static int supported = -1;

        if (supported != -1)
                return supported;

        arch = uname_architecture();
        if (arch < 0) {
                log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                "Failed to determine CPU architecture");
                return supported = 0;
        }

        if (bpf_object_cpu_arch_supported(arch) <= 0) {
                log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "CPU architecture %s is not supported",
                                architecture_to_string(arch));
                return supported = 0;
        }

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0) {
                log_error_errno(r, "Can't determine whether the unified hierarchy is used: %m");
                return supported = 0;
        }
        if (r == 0) {
                log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                "Not running with unified cgroup hierarchy, BPF is not supported");
                return supported = 0;
        }

        /*
         * Load bpf object w/o populating maps to probe whether
         * BPF_PROG_TYPE_CGROUP_SKB program type is supported by kernel and
         * if resource limits permit locking enough memory.
         */
        r = bpf_object_new(restrict_ifaces_hexdump_buffer,
                sizeof(restrict_ifaces_hexdump_buffer), "restrict-ifaces", &obj);
        if (r < 0) {
                log_debug_errno(r, "Failed to create BPF object from hexdump buffer: %m");
                return supported  = 0;
        }

        r = bpf_object_load(obj);
        if (r < 0) {
                log_debug_errno(r, "Failed to load BPF object: %m");
                return supported = 0;
        }

        return supported = 1;
}

int restrict_network_interfaces_install(Unit *u) {
        _cleanup_(bpf_object_freep) struct bpf_object *object = NULL;
        _cleanup_(set_freep) Set *new_progs = NULL;
        _cleanup_(set_freep) Set *old_progs = NULL;
        CGroupContext *cc;
        int r;

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return 0;

        if (cc->restrict_network_interfaces) {
                r = prepare_bpf_object(u,
                        cc->restrict_network_interfaces_is_allow_list,
                        cc->restrict_network_interfaces,
                        &object);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to prepare BPF object: %m");

                r = bpf_object_get_programs(object, &new_progs);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to get BPF programs from BPF object: %m");
        }

        r = cgroup_bpf_detach_programs(u, u->restrict_network_interfaces_progs);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to detach restrict_network_interfaces BPF programs: %m");

        /* Swap pointers to close FDs of detached programs on exit. */
        SWAP_TWO(u->restrict_network_interfaces_progs, old_progs);

        r = cgroup_bpf_attach_programs(u, new_progs, BPF_F_ALLOW_MULTI);
        if (r < 0)
                return log_unit_error_errno(u, r, "Failed to attach restrict_network_interfaces BPF programs: %m");

        /* If attach succeeds, store FDs of loaded programs in unit. */
        SWAP_TWO(new_progs, u->restrict_network_interfaces_progs);

        return 0;
}
#else /* ! BUILD_BPF */
int restrict_network_interfaces_supported(void) {
        return 0;
}

int restrict_network_interfaces_install(Unit *u) {
        return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                        "Failed to install IfacesLock: BPF programs built from source code are not supported: %m");
}
#endif
