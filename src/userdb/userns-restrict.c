/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "userns-restrict.h"

#if BPF_FRAMEWORK

#include <sched.h>

#include "bpf-dlopen.h"
#include "bpf-link.h"
#include "fd-util.h"
#include "fs-util.h"
#include "lsm-util.h"
#include "missing_mount.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "path-util.h"

#define USERNS_MAX (16U*1024U)
#define MOUNTS_MAX 4096U

#define PROGRAM_LINK_PREFIX "/sys/fs/bpf/systemd/userns-restrict/programs"
#define MAP_LINK_PREFIX "/sys/fs/bpf/systemd/userns-restrict/maps"

struct userns_restrict_bpf *userns_restrict_bpf_free(struct userns_restrict_bpf *obj) {
        (void) userns_restrict_bpf__destroy(obj); /* this call is fine with NULL */
        return NULL;
}

static int make_inner_hash_map(void) {
        int fd;

        fd = compat_bpf_map_create(
                        BPF_MAP_TYPE_HASH,
                        NULL,
                        sizeof(int),
                        sizeof(uint32_t),
                        MOUNTS_MAX,
                        NULL);
        if (fd < 0)
                return log_debug_errno(errno, "Failed allocate inner BPF map: %m");

        return fd;
}

int userns_restrict_install(
                bool pin,
                struct userns_restrict_bpf **ret) {

        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *obj = NULL;
        _cleanup_close_ int dummy_mnt_id_hash_fd = -EBADF;
        int r;

        r = lsm_supported("bpf");
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "bpf-lsm not supported, can't lock down user namespace.");

        r = dlopen_bpf();
        if (r < 0)
                return r;

        /* bpf_object__next_map() is not available in libbpf pre-0.7.0, and we want to use it. */
        if (!sym_bpf_object__next_map)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libbpf too old for locking down user namespace.");

        obj = userns_restrict_bpf__open();
        if (!obj)
                return log_error_errno(errno, "Failed to open userns_restrict BPF object: %m");

        if (pin) {
                struct bpf_map *map;

                /* libbpf will only create one level of dirs. Let's create the rest */
                (void) mkdir_p(MAP_LINK_PREFIX, 0755);
                (void) mkdir_p(PROGRAM_LINK_PREFIX, 0755);

                map = sym_bpf_object__next_map(obj->obj, NULL);
                while (map) {
                        _cleanup_free_ char *fn = NULL;

                        fn = path_join(MAP_LINK_PREFIX, sym_bpf_map__name(map));
                        if (!fn)
                                return log_oom();

                        r = sym_bpf_map__set_pin_path(map, fn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set pin path to '%s': %m", fn);

                        map = sym_bpf_object__next_map(obj->obj, map);
                }
        }

        r = sym_bpf_map__set_max_entries(obj->maps.userns_mnt_id_hash, USERNS_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to size userns/mnt_id hash table: %m");

        r = sym_bpf_map__set_max_entries(obj->maps.userns_ringbuf, USERNS_MAX * sizeof(unsigned int));
        if (r < 0)
                return log_error_errno(r, "Failed to size userns ring buffer: %m");

        /* Dummy map to satisfy the verifier */
        dummy_mnt_id_hash_fd = make_inner_hash_map();
        if (dummy_mnt_id_hash_fd < 0)
                return dummy_mnt_id_hash_fd;

        r = sym_bpf_map__set_inner_map_fd(obj->maps.userns_mnt_id_hash, dummy_mnt_id_hash_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to set inner BPF map: %m");

        r = userns_restrict_bpf__load(obj);
        if (r < 0)
                return log_error_errno(r, "Failed to load BPF object: %m");

        for (int i = 0; i < obj->skeleton->prog_cnt; i++) {
                _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
                struct bpf_prog_skeleton *ps = obj->skeleton->progs + i;
                _cleanup_free_ char *fn = NULL;
                bool linked = false;
                const char *e;

                e = startswith(ps->name, "userns_restrict_");
                assert(e);

                if (pin) {
                        fn = path_join(PROGRAM_LINK_PREFIX, e);
                        if (!fn)
                                return log_oom();

                        link = sym_bpf_link__open(fn);
                        r = sym_libbpf_get_error(link);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Unable to open pinned program link: %m");
                                link = NULL;
                        } else {
                                linked = true;
                                log_info("userns-restrict BPF-LSM program %s already attached.", ps->name);
                        }
                }

                if (!link) {
                        link = sym_bpf_program__attach(*ps->prog);
                        r = sym_libbpf_get_error(link);
                        if (r < 0)
                                return log_error_errno(r, "Failed to attach LSM BPF program: %m");

                        log_info("userns-restrict BPF-LSM program %s now attached.", ps->name);
                }

                if (pin && !linked) {
                        assert(fn);

                        r = sym_bpf_link__pin(link, fn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to pin LSM attachment: %m");
                }

                *ps->link = TAKE_PTR(link);
        }

        if (pin) {
                r = sym_bpf_object__pin_maps(obj->obj, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin BPF maps: %m");
        }

        if (ret)
                *ret = TAKE_PTR(obj);

        return 0;
}

int userns_restrict_put_by_inode(
                struct userns_restrict_bpf *obj,
                uint64_t userns_inode,
                bool replace,
                const int mount_fds[],
                size_t n_mount_fds) {

        _cleanup_close_ int inner_map_fd = -EBADF;
        _cleanup_free_ int *mnt_ids = NULL;
        uint64_t ino = userns_inode;
        int r, outer_map_fd;

        assert(obj);
        assert(userns_inode != 0);
        assert(n_mount_fds == 0 || mount_fds);

        /* The BPF map type BPF_MAP_TYPE_HASH_OF_MAPS only supports 32bit keys, and user namespace inode
         * numbers are 32bit too, even though ino_t is 64bit these days. Should we ever run into a 64bit
         * inode let's refuse early, we can't support this with the current BPF code for now. */
        if (userns_inode > UINT32_MAX)
                return -EINVAL;

        mnt_ids = new(int, n_mount_fds);
        if (!mnt_ids)
                return -ENOMEM;

        for (size_t i = 0; i < n_mount_fds; i++) {
                r = path_get_mnt_id_at(mount_fds[i], "", mnt_ids + i);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get mount ID: %m");
        }

        outer_map_fd = sym_bpf_map__fd(obj->maps.userns_mnt_id_hash);
        if (outer_map_fd < 0)
                return log_debug_errno(outer_map_fd, "Failed to get outer BPF map fd: %m");

        if (replace) {
                /* Add if missing, replace if already exists */
                inner_map_fd = make_inner_hash_map();
                if (inner_map_fd < 0)
                        return inner_map_fd;

                r = sym_bpf_map_update_elem(outer_map_fd, &ino, &inner_map_fd, BPF_ANY);
                if (r < 0)
                        return log_debug_errno(errno, "Failed to replace map in inode hash: %m");
        } else {
                /* Let's add an entry for this userns inode if missing. If it exists just extend the existing map. We
                 * might race against each other, hence we try a couple of times */
                for (size_t n_try = 10;; n_try--) {
                        uint32_t innermap_id;

                        if (n_try == 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "Stillcan't create inode entry in BPF map after 10 tries.");

                        r = sym_bpf_map_lookup_elem(outer_map_fd, &ino, &innermap_id);
                        if (r >= 0) {
                                inner_map_fd = sym_bpf_map_get_fd_by_id(innermap_id);
                                if (inner_map_fd < 0)
                                        return log_debug_errno(inner_map_fd, "Failed to get file descriptor for inner map: %m");

                                break;
                        }
                        if (errno != ENOENT)
                                return log_debug_errno(errno, "Failed to look up inode hash entry: %m");

                        /* No entry for this user namespace yet. Let's create one */
                        inner_map_fd = make_inner_hash_map();
                        if (inner_map_fd < 0)
                                return inner_map_fd;

                        r = sym_bpf_map_update_elem(outer_map_fd, &ino, &inner_map_fd, BPF_NOEXIST);
                        if (r >= 0)
                                break;
                        if (errno != EEXIST)
                                return log_debug_errno(errno, "Failed to add mount ID list to inode hash: %m");
                }
        }

        for (size_t i = 0; i < n_mount_fds; i++) {
                uint32_t dummy_value = 1;

                r = sym_bpf_map_update_elem(inner_map_fd, mnt_ids + i, &dummy_value, BPF_ANY);
                if (r < 0)
                        return log_debug_errno(errno, "Failed to add mount ID to map: %m");

                log_debug("Allowing mount %i on userns inode %" PRIu64, mnt_ids[i], ino);
        }

        return 0;
}

int userns_restrict_put_by_fd(
                struct userns_restrict_bpf *obj,
                int userns_fd,
                bool replace,
                const int mount_fds[],
                size_t n_mount_fds) {

        struct stat st;
        int r;

        assert(obj);
        assert(userns_fd >= 0);
        assert(n_mount_fds == 0 || mount_fds);

        r = fd_is_ns(userns_fd, CLONE_NEWUSER);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if file descriptor is user namespace: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADF), "User namespace fd is not actually a user namespace fd.");

        if (fstat(userns_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace: %m");

        return userns_restrict_put_by_inode(
                        obj,
                        st.st_ino,
                        replace,
                        mount_fds,
                        n_mount_fds);
}

int userns_restrict_reset_by_inode(
                struct userns_restrict_bpf *obj,
                uint64_t ino) {

        int r, outer_map_fd;
        unsigned u;

        assert(obj);
        assert(ino != 0);

        if (ino > UINT32_MAX) /* inodes larger than 32bit are definitely not included in our map, exit early */
                return 0;

        outer_map_fd = sym_bpf_map__fd(obj->maps.userns_mnt_id_hash);
        if (outer_map_fd < 0)
                return log_debug_errno(outer_map_fd, "Failed to get outer BPF map fd: %m");

        u = (uint32_t) ino;

        r = sym_bpf_map_delete_elem(outer_map_fd, &u);
        if (r < 0)
                return log_debug_errno(outer_map_fd, "Failed to remove entry for inode %" PRIu64 " from outer map: %m", ino);

        return 0;
}

#endif
