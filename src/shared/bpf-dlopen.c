/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "bpf-dlopen.h"
#include "log.h"
#include "strv.h"

#if HAVE_LIBBPF
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

/* compat symbols removed in libbpf 1.0 */
int (*sym_bpf_create_map)(enum bpf_map_type,  int key_size, int value_size, int max_entries, __u32 map_flags);
bool (*sym_bpf_probe_prog_type)(enum bpf_prog_type, __u32);

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
        void *dl;
        int r;

        dl = dlopen("libbpf.so.1", RTLD_LAZY);
        if (!dl) {
                /* libbpf < 1.0.0 (we rely on 0.1.0+) provide most symbols we care about, but
                 * unfortunately not all until 0.7.0. See bpf-compat.h for more details.
                 * Once we consider we can assume 0.7+ is present we can just use the same symbol
                 * list for both files, and when we assume 1.0+ is present we can remove this dlopen */
                dl = dlopen("libbpf.so.0", RTLD_LAZY);
                if (!dl)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "neither libbpf.so.1 nor libbpf.so.0 are installed: %s", dlerror());

                /* symbols deprecated in 1.0 we use as compat */
                r = dlsym_many_or_warn(dl, LOG_DEBUG,
                                DLSYM_ARG(bpf_create_map),
                                DLSYM_ARG(bpf_probe_prog_type));
        } else {
                /* symbols available from 0.7.0 */
                r = dlsym_many_or_warn(dl, LOG_DEBUG,
                                DLSYM_ARG(bpf_map_create),
                                DLSYM_ARG(libbpf_probe_bpf_prog_type));
        }

        r = dlsym_many_or_warn(
                        dl, LOG_DEBUG,
                        DLSYM_ARG(bpf_link__destroy),
                        DLSYM_ARG(bpf_link__fd),
                        DLSYM_ARG(bpf_map__fd),
                        DLSYM_ARG(bpf_map__name),
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
