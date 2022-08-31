/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "bpf-dlopen.h"
#include "log.h"

#if HAVE_LIBBPF
static void *bpf_dl = NULL;

struct bpf_link* (*sym_bpf_program__attach_cgroup)(struct bpf_program *, int);
struct bpf_link* (*sym_bpf_program__attach_lsm)(struct bpf_program *);
int (*sym_bpf_link__fd)(const struct bpf_link *);
int (*sym_bpf_link__destroy)(struct bpf_link *);
int (*sym_bpf_map__fd)(const struct bpf_map *);
const char* (*sym_bpf_map__name)(const struct bpf_map *);
int (*sym_bpf_map_create)(enum bpf_map_type,  const char *, __u32, __u32, __u32, const struct bpf_map_create_opts *);
int (*sym_bpf_map__set_max_entries)(struct bpf_map *, __u32);
int (*sym_bpf_map_update_elem)(int, const void *, const void *, __u64);
int (*sym_bpf_map_delete_elem)(int, const void *);
int (*sym_bpf_map__set_inner_map_fd)(struct bpf_map *, int);
int (*sym_bpf_object__open_skeleton)(struct bpf_object_skeleton *, const struct bpf_object_open_opts *);
int (*sym_bpf_object__load_skeleton)(struct bpf_object_skeleton *);
int (*sym_bpf_object__attach_skeleton)(struct bpf_object_skeleton *);
void (*sym_bpf_object__detach_skeleton)(struct bpf_object_skeleton *);
void (*sym_bpf_object__destroy_skeleton)(struct bpf_object_skeleton *);
bool (*sym_libbpf_probe_bpf_prog_type)(enum bpf_prog_type, const void *);
const char* (*sym_bpf_program__name)(const struct bpf_program *);
libbpf_print_fn_t (*sym_libbpf_set_print)(libbpf_print_fn_t);
long (*sym_libbpf_get_error)(const void *);

_printf_(2,0)
static int bpf_print_func(enum libbpf_print_level level, const char *fmt, va_list ap) {
#if !LOG_TRACE
        /* libbpf logs a lot of details at its debug level, which we don't need to see. */
        if (level == LIBBPF_DEBUG)
                return 0;
#endif
        /* All other levels are downgraded to LOG_DEBUG */

        /* errno is used here, on the assumption that if the log message uses %m, errno will be set to
         * something useful. Otherwise, it shouldn't matter, we may pass 0 or some bogus value. */
        return log_internalv(LOG_DEBUG, errno, NULL, 0, NULL, fmt, ap);
}

int dlopen_bpf(void) {
        int r;

        r = dlopen_many_sym_or_warn(
                        &bpf_dl, "libbpf.so.0", LOG_DEBUG,
                        DLSYM_ARG(bpf_link__destroy),
                        DLSYM_ARG(bpf_link__fd),
                        DLSYM_ARG(bpf_map__fd),
                        DLSYM_ARG(bpf_map__name),
                        DLSYM_ARG(bpf_map_create),
                        DLSYM_ARG(bpf_map__set_max_entries),
                        DLSYM_ARG(bpf_map_update_elem),
                        DLSYM_ARG(bpf_map_delete_elem),
                        DLSYM_ARG(bpf_map__set_inner_map_fd),
                        DLSYM_ARG(bpf_object__open_skeleton),
                        DLSYM_ARG(bpf_object__load_skeleton),
                        DLSYM_ARG(bpf_object__attach_skeleton),
                        DLSYM_ARG(bpf_object__detach_skeleton),
                        DLSYM_ARG(bpf_object__destroy_skeleton),
                        DLSYM_ARG(bpf_program__attach_cgroup),
                        DLSYM_ARG(bpf_program__attach_lsm),
                        DLSYM_ARG(bpf_program__name),
                        DLSYM_ARG(libbpf_probe_bpf_prog_type),
                        DLSYM_ARG(libbpf_set_print),
                        DLSYM_ARG(libbpf_get_error));
        if (r < 0)
                return r;

        /* We set the print helper unconditionally. Otherwise libbpf will emit not useful log messages. */
        (void) sym_libbpf_set_print(bpf_print_func);
        return r;
}

#else

int dlopen_bpf(void) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "libbpf support is not compiled in.");
}
#endif
