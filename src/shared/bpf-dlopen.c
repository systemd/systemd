/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "bpf-dlopen.h"
#include "log.h"

#if HAVE_LIBBPF
static void *bpf_dl = NULL;

struct bpf_link* (*sym_bpf_program__attach_cgroup)(struct bpf_program *, int);
struct bpf_link* (*sym_bpf_program__attach_lsm)(struct bpf_program *);
long (*sym_libbpf_get_error)(const void *);
int (*sym_bpf_link__fd)(const struct bpf_link *);
int (*sym_bpf_link__destroy)(struct bpf_link *);
int (*sym_bpf_map__fd)(const struct bpf_map *);
const char* (*sym_bpf_map__name)(const struct bpf_map *);
int (*sym_bpf_create_map)(enum bpf_map_type,  int key_size, int value_size, int max_entries, __u32 map_flags);
int (*sym_bpf_map__resize)(struct bpf_map *, __u32);
int (*sym_bpf_map_update_elem)(int, const void *, const void *, __u64);
int (*sym_bpf_map_delete_elem)(int, const void *);
int (*sym_bpf_map__set_inner_map_fd)(struct bpf_map *, int);
int (*sym_bpf_object__open_skeleton)(struct bpf_object_skeleton *, const struct bpf_object_open_opts *);
int (*sym_bpf_object__load_skeleton)(struct bpf_object_skeleton *);
int (*sym_bpf_object__attach_skeleton)(struct bpf_object_skeleton *);
void (*sym_bpf_object__detach_skeleton)(struct bpf_object_skeleton *);
void (*sym_bpf_object__destroy_skeleton)(struct bpf_object_skeleton *);
bool (*sym_bpf_probe_prog_type)(enum bpf_prog_type, __u32);
const char* (*sym_bpf_program__name)(const struct bpf_program *);

int dlopen_bpf(void) {
        return dlopen_many_sym_or_warn(
                        &bpf_dl, "libbpf.so.0", LOG_DEBUG,
                        DLSYM_ARG(bpf_link__destroy),
                        DLSYM_ARG(bpf_link__fd),
                        DLSYM_ARG(bpf_map__fd),
                        DLSYM_ARG(bpf_map__name),
                        DLSYM_ARG(bpf_create_map),
                        DLSYM_ARG(bpf_map__resize),
                        DLSYM_ARG(bpf_map_update_elem),
                        DLSYM_ARG(bpf_map_delete_elem),
                        DLSYM_ARG(bpf_map__set_inner_map_fd),
                        DLSYM_ARG(bpf_object__open_skeleton),
                        DLSYM_ARG(bpf_object__load_skeleton),
                        DLSYM_ARG(bpf_object__attach_skeleton),
                        DLSYM_ARG(bpf_object__detach_skeleton),
                        DLSYM_ARG(bpf_object__destroy_skeleton),
                        DLSYM_ARG(bpf_probe_prog_type),
                        DLSYM_ARG(bpf_program__attach_cgroup),
                        DLSYM_ARG(bpf_program__attach_lsm),
                        DLSYM_ARG(bpf_program__name),
                        DLSYM_ARG(libbpf_get_error));
}

#else

int dlopen_bpf(void) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "libbpf support is not compiled in.");
}
#endif
