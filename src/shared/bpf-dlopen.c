/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "bpf-dlopen.h"
#include "log.h"
#include "strv.h"

#if HAVE_LIBBPF

/* libbpf changed types of function prototypes around, so we need to disable some type checking for older
 * libbpf. We consider everything older than 0.7 too old for accurate type checks. */
#if defined(__LIBBPF_CURRENT_VERSION_GEQ)
#if __LIBBPF_CURRENT_VERSION_GEQ(0, 7)
#define MODERN_LIBBPF 1
#endif
#endif
#if !defined(MODERN_LIBBPF)
#define MODERN_LIBBPF 0
#endif

DLSYM_PROTOTYPE(bpf_link__destroy) = NULL;
DLSYM_PROTOTYPE(bpf_link__fd) = NULL;
DLSYM_PROTOTYPE(bpf_link__open) = NULL;
DLSYM_PROTOTYPE(bpf_link__pin) = NULL;
DLSYM_PROTOTYPE(bpf_map__fd) = NULL;
DLSYM_PROTOTYPE(bpf_map__name) = NULL;
DLSYM_PROTOTYPE(bpf_map__set_inner_map_fd) = NULL;
DLSYM_PROTOTYPE(bpf_map__set_max_entries) = NULL;
DLSYM_PROTOTYPE(bpf_map__set_pin_path) = NULL;
DLSYM_PROTOTYPE(bpf_map_delete_elem) = NULL;
DLSYM_PROTOTYPE(bpf_map_get_fd_by_id) = NULL;
DLSYM_PROTOTYPE(bpf_map_lookup_elem) = NULL;
DLSYM_PROTOTYPE(bpf_map_update_elem) = NULL;
DLSYM_PROTOTYPE(bpf_object__attach_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__destroy_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__detach_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__load_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__name) = NULL;
DLSYM_PROTOTYPE(bpf_object__open_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__pin_maps) = NULL;
DLSYM_PROTOTYPE(bpf_program__attach) = NULL;
DLSYM_PROTOTYPE(bpf_program__attach_cgroup) = NULL;
DLSYM_PROTOTYPE(bpf_program__attach_lsm) = NULL;
DLSYM_PROTOTYPE(bpf_program__name) = NULL;
DLSYM_PROTOTYPE(libbpf_get_error) = NULL;
DLSYM_PROTOTYPE(libbpf_set_print) = NULL;
DLSYM_PROTOTYPE(ring_buffer__epoll_fd) = NULL;
DLSYM_PROTOTYPE(ring_buffer__free) = NULL;
DLSYM_PROTOTYPE(ring_buffer__new) = NULL;
DLSYM_PROTOTYPE(ring_buffer__poll) = NULL;

/* new symbols available from libbpf 0.7.0 */
int (*sym_bpf_map_create)(enum bpf_map_type,  const char *, __u32, __u32, __u32, const struct bpf_map_create_opts *);
int (*sym_libbpf_probe_bpf_prog_type)(enum bpf_prog_type, const void *);
struct bpf_map* (*sym_bpf_object__next_map)(const struct bpf_object *obj, const struct bpf_map *map);

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

        ELF_NOTE_DLOPEN("bpf",
                        "Support firewalling and sandboxing with BPF",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libbpf.so.1", "libbpf.so.0");

        DISABLE_WARNING_DEPRECATED_DECLARATIONS;

        dl = dlopen("libbpf.so.1", RTLD_NOW|RTLD_NODELETE);
        if (!dl) {
                /* libbpf < 1.0.0 (we rely on 0.1.0+) provide most symbols we care about, but
                 * unfortunately not all until 0.7.0. See bpf-compat.h for more details.
                 * Once we consider we can assume 0.7+ is present we can just use the same symbol
                 * list for both files, and when we assume 1.0+ is present we can remove this dlopen */
                dl = dlopen("libbpf.so.0", RTLD_NOW|RTLD_NODELETE);
                if (!dl)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "neither libbpf.so.1 nor libbpf.so.0 are installed: %s", dlerror());

                log_debug("Loaded 'libbpf.so.0' via dlopen()");

                /* symbols deprecated in 1.0 we use as compat */
                r = dlsym_many_or_warn(
                                dl, LOG_DEBUG,
#if MODERN_LIBBPF
                                /* Don't exist anymore in new libbpf, hence cannot type check them */
                                DLSYM_ARG_FORCE(bpf_create_map),
                                DLSYM_ARG_FORCE(bpf_probe_prog_type)
#else
                                DLSYM_ARG(bpf_create_map),
                                DLSYM_ARG(bpf_probe_prog_type)
#endif
                );

                /* NB: we don't try to load bpf_object__next_map() on old versions */
        } else {
                log_debug("Loaded 'libbpf.so.1' via dlopen()");

                /* symbols available from 0.7.0 */
                r = dlsym_many_or_warn(
                                dl, LOG_DEBUG,
#if MODERN_LIBBPF
                                DLSYM_ARG(bpf_map_create),
                                DLSYM_ARG(libbpf_probe_bpf_prog_type),
                                DLSYM_ARG(bpf_object__next_map)
#else
                                /* These symbols did not exist in old libbpf, hence we cannot type check them */
                                DLSYM_ARG_FORCE(bpf_map_create),
                                DLSYM_ARG_FORCE(libbpf_probe_bpf_prog_type),
                                DLSYM_ARG_FORCE(bpf_object__next_map)
#endif
                );
        }
        if (r < 0)
                return r;

        r = dlsym_many_or_warn(
                        dl, LOG_DEBUG,
                        DLSYM_ARG(bpf_link__destroy),
                        DLSYM_ARG(bpf_link__fd),
                        DLSYM_ARG(bpf_link__open),
                        DLSYM_ARG(bpf_link__pin),
                        DLSYM_ARG(bpf_map__fd),
                        DLSYM_ARG(bpf_map__name),
                        DLSYM_ARG(bpf_map__set_inner_map_fd),
                        DLSYM_ARG(bpf_map__set_max_entries),
                        DLSYM_ARG(bpf_map__set_pin_path),
                        DLSYM_ARG(bpf_map_delete_elem),
                        DLSYM_ARG(bpf_map_get_fd_by_id),
                        DLSYM_ARG(bpf_map_lookup_elem),
                        DLSYM_ARG(bpf_map_update_elem),
                        DLSYM_ARG(bpf_object__attach_skeleton),
                        DLSYM_ARG(bpf_object__destroy_skeleton),
                        DLSYM_ARG(bpf_object__detach_skeleton),
                        DLSYM_ARG(bpf_object__load_skeleton),
                        DLSYM_ARG(bpf_object__name),
                        DLSYM_ARG(bpf_object__open_skeleton),
                        DLSYM_ARG(bpf_object__pin_maps),
#if MODERN_LIBBPF
                        DLSYM_ARG(bpf_program__attach),
                        DLSYM_ARG(bpf_program__attach_cgroup),
                        DLSYM_ARG(bpf_program__attach_lsm),
#else
                        /* libbpf added a "const" to function parameters where it should not have, ignore this type incompatibility */
                        DLSYM_ARG_FORCE(bpf_program__attach),
                        DLSYM_ARG_FORCE(bpf_program__attach_cgroup),
                        DLSYM_ARG_FORCE(bpf_program__attach_lsm),
#endif
                        DLSYM_ARG(bpf_program__name),
                        DLSYM_ARG(libbpf_get_error),
                        DLSYM_ARG(libbpf_set_print),
                        DLSYM_ARG(ring_buffer__epoll_fd),
                        DLSYM_ARG(ring_buffer__free),
                        DLSYM_ARG(ring_buffer__new),
                        DLSYM_ARG(ring_buffer__poll));
        if (r < 0)
                return r;

        /* We set the print helper unconditionally. Otherwise libbpf will emit not useful log messages. */
        (void) sym_libbpf_set_print(bpf_print_func);

        REENABLE_WARNING;

        return r;
}

int bpf_get_error_translated(const void *ptr) {
        int r;

        r = sym_libbpf_get_error(ptr);

        switch (r) {
        case -524:
                /* Workaround for kernel bug, BPF returns an internal error instead of translating it, until
                 * it is fixed:
                 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/errno.h?h=v6.9&id=a38297e3fb012ddfa7ce0321a7e5a8daeb1872b6#n27
                 */
                return -EOPNOTSUPP;
        default:
                return r;
        }
}

#else

int dlopen_bpf(void) {
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "libbpf support is not compiled in.");
}
#endif
