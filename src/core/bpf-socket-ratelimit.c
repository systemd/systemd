/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "bpf-socket-ratelimit.h"
#include "cgroup.h"
#include "fd-util.h"
#include "log.h"
#include "lsm-util.h"
#include "manager.h"
#include "mkdir.h"
#include "path-util.h"
#include "ratelimit.h"
#include "strv.h"
#include "unit.h"

#if BPF_FRAMEWORK && HAVE_BPF_SOCK_READ_XATTR
#include "bpf-util.h"
#include "bpf-link.h"
#include "socket-ratelimit-skel.h"

#define SOCKET_RATELIMIT_MAP_PIN_PREFIX "/sys/fs/bpf/systemd/socket-ratelimit"

static struct socket_ratelimit_bpf *socket_ratelimit_bpf_free(struct socket_ratelimit_bpf *obj) {
        socket_ratelimit_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct socket_ratelimit_bpf*, socket_ratelimit_bpf_free);

bool bpf_socket_ratelimit_supported(void) {
        static int supported = -1;
        int r;

        if (supported >= 0)
                return supported;

        r = lsm_supported("bpf");
        if (r == -ENOPKG) {
                log_debug_errno(r, "bpf-socket-ratelimit: securityfs not mounted, BPF LSM support not available.");
                return (supported = false);
        }
        if (r < 0) {
                log_warning_errno(r, "bpf-socket-ratelimit: Can't determine whether the BPF LSM module is used: %m");
                return (supported = false);
        }
        if (r == 0) {
                log_info("bpf-socket-ratelimit: BPF LSM hook not enabled in the kernel, BPF LSM not supported.");
                return (supported = false);
        }

        if (DLOPEN_BPF(LOG_WARNING, recommended) < 0)
                return (supported = false);

        return (supported = true);
}

int bpf_socket_ratelimit_setup(Manager *m) {
        _cleanup_(socket_ratelimit_bpf_freep) struct socket_ratelimit_bpf *obj = NULL;
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        struct bpf_map *map;
        int r;

        assert(m);

        if (!MANAGER_IS_SYSTEM(m))
                return 0;

        if (m->socket_ratelimit)
                return 0;

        if (!bpf_socket_ratelimit_supported())
                return 0;

        r = dlopen_bpf(LOG_WARNING);
        if (r < 0)
                return r;

        obj = socket_ratelimit_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-socket-ratelimit: Failed to open BPF object: %m");

        (void) mkdir_p(SOCKET_RATELIMIT_MAP_PIN_PREFIX, 0755);

        map = sym_bpf_object__next_map(obj->obj, NULL);
        while (map) {
                const char *name = sym_bpf_map__name(map);

                if (!STR_IN_SET(name, "socket_ratelimit_flag_map", "socket_ratelimit_map" )) {
                        map = sym_bpf_object__next_map(obj->obj, map);
                        continue;
                }

                _cleanup_free_ char *fn = NULL;

                fn = path_join(SOCKET_RATELIMIT_MAP_PIN_PREFIX, name);
                if (!fn)
                        return log_oom();

                r = sym_bpf_map__set_pin_path(map, fn);
                if (r < 0)
                        return log_error_errno(r, "bpf-socket-ratelimit: Failed to set pin path to '%s': %m", fn);

                map = sym_bpf_object__next_map(obj->obj, map);
        }

        r = socket_ratelimit_bpf__load(obj);
        if (r != 0)
                return log_error_errno(r, "bpf-socket-ratelimit: Failed to load BPF object: %m");

        r = sym_bpf_object__pin_maps(obj->obj, NULL);
        if (r < 0)
                return log_error_errno(r, "bpf-socket-ratelimit: Failed to pin BPF maps: %m");

        link = sym_bpf_program__attach_lsm(obj->progs.sd_socket_ratelimit_send);
        r = bpf_get_error_translated(link);
        if (r != 0)
                return log_error_errno(r, "bpf-socket-ratelimit: Failed to attach '%s' LSM BPF program: %m",
                                       sym_bpf_program__name(obj->progs.sd_socket_ratelimit_send));
        obj->links.sd_socket_ratelimit_send = TAKE_PTR(link);

        link = sym_bpf_program__attach_lsm(obj->progs.sd_socket_ratelimit_bind);
        r = bpf_get_error_translated(link);
        if (r != 0)
                return log_error_errno(r, "bpf-socket-ratelimit: Failed to attach '%s' LSM BPF program: %m",
                                       sym_bpf_program__name(obj->progs.sd_socket_ratelimit_bind));
        obj->links.sd_socket_ratelimit_bind = TAKE_PTR(link);

        m->socket_ratelimit = TAKE_PTR(obj);

        m->initial_socket_ratelimit_send_link_fd = safe_close(m->initial_socket_ratelimit_send_link_fd);
        m->initial_socket_ratelimit_bind_link_fd = safe_close(m->initial_socket_ratelimit_bind_link_fd);

        return 0;
}

int bpf_socket_ratelimit_install(Unit *u, uint64_t interval, uint64_t burst) {
        struct {
                uint32_t lock;
                uint64_t interval;
                uint32_t burst;
                uint32_t num;
                uint64_t begin;
        } value = { .interval = interval,
                    .burst = burst };
        CGroupRuntime *crt;
        int r;

        assert(u);

        if (!u->manager->socket_ratelimit)
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        if (crt->cgroup_id == 0)
                return 0;

        uint64_t key = crt->cgroup_id;
        r = sym_bpf_map__update_elem(u->manager->socket_ratelimit->maps.socket_ratelimit_map, &key, sizeof(key), &value, sizeof(value), BPF_NOEXIST);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-socket-ratelimit: Failed to add cgroup to rate limit map: %m");

        return 0;
}

int bpf_socket_ratelimit_cleanup(Unit *u) {
        CGroupRuntime *crt;
        int fd;

        assert(u);
        assert(u->manager);

        if (!u->manager->socket_ratelimit)
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        if (crt->cgroup_id == 0)
                return 0;

        fd = sym_bpf_map__fd(u->manager->socket_ratelimit->maps.socket_ratelimit_map);
        if (fd < 0)
                return log_unit_error_errno(u, fd, "bpf-socket-ratelimit: Failed to get BPF map fd: %m");

        if (sym_bpf_map_delete_elem(fd, &crt->cgroup_id) != 0 && errno != ENOENT)
                return log_unit_debug_errno(u, errno, "bpf-socket-ratelimit: Failed to remove cgroup from rate limit map: %m");

        return 0;
}

void bpf_socket_ratelimit_destroy(struct socket_ratelimit_bpf *obj) {
        socket_ratelimit_bpf__destroy(obj);
}

int bpf_socket_ratelimit_serialize(Manager *m, FILE *f, FDSet *fds) {
        int r;

        assert(m);
        assert(f);
        assert(fds);

        if (!m->socket_ratelimit)
                return 0;

        r = bpf_serialize_link(f, fds, "socket-ratelimit-bind-fd", m->socket_ratelimit->links.sd_socket_ratelimit_bind);
        if (r < 0)
                return r;

        return bpf_serialize_link(f, fds, "socket-ratelimit-send-fd", m->socket_ratelimit->links.sd_socket_ratelimit_send);
}

#else /* ! BPF_FRAMEWORK || ! HAVE_BPF_SOCK_READ_XATTR */

bool bpf_socket_ratelimit_supported(void) {
        return false;
}

int bpf_socket_ratelimit_setup(Manager *m) {
        return 0;
}

int bpf_socket_ratelimit_install(Unit *u, uint64_t interval, uint64_t burst) {
        return 0;
}

int bpf_socket_ratelimit_cleanup(Unit *u) {
        return 0;
}

void bpf_socket_ratelimit_destroy(struct socket_ratelimit_bpf *obj) {
}

int bpf_socket_ratelimit_serialize(Manager *m, FILE *f, FDSet *fds) {
        return 0;
}

#endif
