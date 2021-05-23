/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "bpf-dlopen.h"

#if HAVE_LIBBPF
static void *bpf_dl = NULL;

struct bpf_link* (*sym_bpf_program__attach_cgroup)(struct bpf_program *, int);
long (*sym_libbpf_get_error)(const void *);
int (*sym_bpf_link__fd)(const struct bpf_link *);
int (*sym_bpf_link__destroy)(struct bpf_link *);
int (*sym_bpf_map__fd)(const struct bpf_map *);
const char* (*sym_bpf_map__name)(const struct bpf_map *);
int (*sym_bpf_map__resize)(struct bpf_map *, __u32);
int (*sym_bpf_map_update_elem)(int, const void *, const void *, __u64);
int (*sym_bpf_object__open_skeleton)(struct bpf_object_skeleton *, const struct bpf_object_open_opts *);
int (*sym_bpf_object__load_skeleton)(struct bpf_object_skeleton *);
int (*sym_bpf_object__attach_skeleton)(struct bpf_object_skeleton *);
void (*sym_bpf_object__detach_skeleton)(struct bpf_object_skeleton *);
void (*sym_bpf_object__destroy_skeleton)(struct bpf_object_skeleton *);
bool (*sym_bpf_probe_prog_type)(enum bpf_prog_type, __u32);
const char* (*sym_bpf_program__name)(const struct bpf_program *);

int dlopen_bpf(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (bpf_dl)
                return 0; /* Already loaded */

        dl = dlopen("libbpf.so.0", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libbpf is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_ERR,
                        DLSYM_ARG(bpf_link__destroy),
                        DLSYM_ARG(bpf_link__fd),
                        DLSYM_ARG(bpf_map__fd),
                        DLSYM_ARG(bpf_map__name),
                        DLSYM_ARG(bpf_map__resize),
                        DLSYM_ARG(bpf_map_update_elem),
                        DLSYM_ARG(bpf_object__open_skeleton),
                        DLSYM_ARG(bpf_object__load_skeleton),
                        DLSYM_ARG(bpf_object__attach_skeleton),
                        DLSYM_ARG(bpf_object__detach_skeleton),
                        DLSYM_ARG(bpf_object__destroy_skeleton),
                        DLSYM_ARG(bpf_probe_prog_type),
                        DLSYM_ARG(bpf_program__attach_cgroup),
                        DLSYM_ARG(bpf_program__name),
                        DLSYM_ARG(libbpf_get_error),
                        NULL);
        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to, after all this
         * was traditionally a regular shared library dependency which lives forever too. */
        bpf_dl = TAKE_PTR(dl);

        return 1;
}

#else

int dlopen_bpf(void) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "libbpf support is not compiled in.");
}
#endif
