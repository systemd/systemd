/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bpf-notify-ratelimit.h"
#include "cgroup.h"
#include "fd-util.h"
#include "manager.h"
#include "ratelimit.h"
#include "unit.h"

#if BPF_FRAMEWORK
#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "bpf/notify-ratelimit/notify-ratelimit-skel.h"

#define NOTIFY_RATELIMIT_HASH_SIZE_MAX 2048
#define NOTIFY_RATELIMIT_INTERVAL (1*USEC_PER_SEC)
#define NOTIFY_RATELIMIT_BURST 10

static struct notify_ratelimit_bpf *notify_ratelimit_bpf_free(struct notify_ratelimit_bpf *obj) {
        notify_ratelimit_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct notify_ratelimit_bpf *, notify_ratelimit_bpf_free);

static int bpf_notify_ratelimit_setup(Manager *m) {
        _cleanup_(notify_ratelimit_bpf_freep) struct notify_ratelimit_bpf *obj = NULL;
        int r;

        if (m->notify_ratelimit)
                return 0;

        r = dlopen_bpf_full(LOG_WARNING);
        if (r < 0)
                return r;

        obj = notify_ratelimit_bpf__open();
        if (!obj)
                return log_error_errno(errno, "bpf-notify-ratelimit: Failed to open BPF object: %m");

        r = notify_ratelimit_bpf__load(obj);
        if (r != 0)
                return log_error_errno(r, "bpf-notify-ratelimit: Failed to load BPF object: %m");

        m->notify_ratelimit = TAKE_PTR(obj);

        return 0;
}

int bpf_notify_ratelimit_install(Unit *u) {
        _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
        _cleanup_free_ char *cgroup_path = NULL;
        _cleanup_close_ int cgroup_fd = -EBADF;
        RateLimit value = { NOTIFY_RATELIMIT_INTERVAL, NOTIFY_RATELIMIT_BURST };
        CGroupRuntime *crt;
        int r;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        if (crt->cgroup_id == 0)
                return 0;

        if (crt->bpf_notify_ratelimit_link)
                return 0;

        r = bpf_notify_ratelimit_setup(u->manager);
        if (r < 0)
                return r;

        uint64_t key = crt->cgroup_id;
        r = sym_bpf_map__update_elem(u->manager->notify_ratelimit->maps.notify_ratelimit_hash, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-notify-ratelimit: Failed to add ratelimiter instance to BPF map: %m");

        r = cg_get_path(crt->cgroup_path, /* suffix= */ NULL, &cgroup_path);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-notify-ratelimit: Failed to get cgroup path: %m");

        cgroup_fd = open(cgroup_path, O_RDONLY | O_CLOEXEC, 0);
        if (cgroup_fd < 0)
                return log_unit_error_errno(u, errno, "bpf-notify-ratelimit: Failed to open cgroup %s for reading: %m", cgroup_path);

        link = sym_bpf_program__attach_cgroup(u->manager->notify_ratelimit->progs.sd_notify_ratelimit, cgroup_fd);
        r = bpf_get_error_translated(link);
        if (r != 0)
                return log_unit_error_errno(u, r, "bpf-notify-ratelimit: Failed to link '%s' cgroup-bpf program: %m",
                                            sym_bpf_program__name(u->manager->notify_ratelimit->progs.sd_notify_ratelimit));

        crt->bpf_notify_ratelimit_link = TAKE_PTR(link);
        crt->initial_notify_ratelimit_link_fd = safe_close(crt->initial_notify_ratelimit_link_fd);

        return 0;
}

int bpf_notify_ratelimit_cleanup(Unit *u) {
        CGroupRuntime *crt;

        assert(u);
        assert(u->manager);

        if (!u->manager->notify_ratelimit)
                return 0;

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        if (crt->cgroup_id == 0)
                return 0;

        int fd = sym_bpf_map__fd(u->manager->notify_ratelimit->maps.notify_ratelimit_hash);
        if (fd < 0)
                return log_unit_error_errno(u, fd, "bpf-notify-ratelimit: Failed to get BPF map fd: %m");

        if (sym_bpf_map_delete_elem(fd, &crt->cgroup_id) != 0 && errno != ENOENT)
                return log_unit_debug_errno(u, errno, "bpf-notify-ratelimit: Failed to delete cgroup entry from notify socket ratelimiter BPF map: %m");

        crt->bpf_notify_ratelimit_link = bpf_link_free(crt->bpf_notify_ratelimit_link);

        return 0;
}

void bpf_notify_ratelimit_destroy(struct notify_ratelimit_bpf *obj) {
        notify_ratelimit_bpf__destroy(obj);
}

int bpf_notify_ratelimit_serialize(Unit *u, FILE *f, FDSet *fds) {
        CGroupRuntime *crt;

        assert(u);

        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        return bpf_serialize_link(f, fds, "notify-ratelimit-bpf-fd", crt->bpf_notify_ratelimit_link);
}

#else /* ! BPF_FRAMEWORK */
int bpf_notify_ratelimit_install(Unit *u) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-notify-ratelimit: BPF framework is not supported.");
}

int bpf_notify_ratelimit_cleanup(Unit *u) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-notify-ratelimit: BPF framework is not supported.");
}

void bpf_notify_ratelimit_destroy(struct notify_ratelimit_bpf *obj) {
        return;
}

int bpf_notify_ratelimit_serialize(Unit *u, FILE *f, FDSet *fds) {
        return 0;
}
#endif
