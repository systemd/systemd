/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bpf-util.h"
#include "dlfcn-util.h"
#include "initrd-util.h"
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

static DLSYM_PROTOTYPE(libbpf_get_error) = NULL;

DLSYM_PROTOTYPE(bpf_create_map) = NULL;
DLSYM_PROTOTYPE(bpf_link__destroy) = NULL;
DLSYM_PROTOTYPE(bpf_link__fd) = NULL;
DLSYM_PROTOTYPE(bpf_link__open) = NULL;
DLSYM_PROTOTYPE(bpf_link__pin) = NULL;
DLSYM_PROTOTYPE(bpf_map__fd) = NULL;
DLSYM_PROTOTYPE(bpf_map__name) = NULL;
DLSYM_PROTOTYPE(bpf_map__set_inner_map_fd) = NULL;
DLSYM_PROTOTYPE(bpf_map__set_max_entries) = NULL;
DLSYM_PROTOTYPE(bpf_map__set_pin_path) = NULL;
DLSYM_PROTOTYPE(bpf_map_create) = NULL;
DLSYM_PROTOTYPE(bpf_map_delete_elem) = NULL;
DLSYM_PROTOTYPE(bpf_map_get_fd_by_id) = NULL;
DLSYM_PROTOTYPE(bpf_map_lookup_elem) = NULL;
DLSYM_PROTOTYPE(bpf_map_update_elem) = NULL;
DLSYM_PROTOTYPE(bpf_obj_get_info_by_fd) = NULL;
DLSYM_PROTOTYPE(bpf_object__attach_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__destroy_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__detach_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__load_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__name) = NULL;
DLSYM_PROTOTYPE(bpf_object__next_map) = NULL;
DLSYM_PROTOTYPE(bpf_object__open_skeleton) = NULL;
DLSYM_PROTOTYPE(bpf_object__pin_maps) = NULL;
DLSYM_PROTOTYPE(bpf_program__attach) = NULL;
DLSYM_PROTOTYPE(bpf_program__attach_cgroup) = NULL;
DLSYM_PROTOTYPE(bpf_program__attach_lsm) = NULL;
DLSYM_PROTOTYPE(bpf_program__name) = NULL;
DLSYM_PROTOTYPE(bpf_program__set_autoload) = NULL;
static int missing_bpf_token_create(int bpffs_fd, struct bpf_token_create_opts *opts) {
        return -ENOSYS;
}
DLSYM_PROTOTYPE(bpf_token_create) = missing_bpf_token_create;
DLSYM_PROTOTYPE(libbpf_set_print) = NULL;
DLSYM_PROTOTYPE(ring_buffer__epoll_fd) = NULL;
DLSYM_PROTOTYPE(ring_buffer__free) = NULL;
DLSYM_PROTOTYPE(ring_buffer__new) = NULL;
DLSYM_PROTOTYPE(ring_buffer__poll) = NULL;

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

#endif

int dlopen_bpf(int log_level) {
#if HAVE_LIBBPF
        static void *bpf_dl = NULL;
        static int cached = 0;
        int r = -ENOENT;

        if (bpf_dl)
                return 1; /* Already loaded */

        if (cached < 0)
                return cached; /* Already tried, and failed. */

        LIBBPF_NOTE(suggested);

        DISABLE_WARNING_DEPRECATED_DECLARATIONS;

        FOREACH_STRING(soname, "libbpf.so.1", "libbpf.so.0") {
                r = dlopen_many_sym_or_warn(
                                &bpf_dl, soname, LOG_DEBUG,
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
                                DLSYM_ARG(bpf_obj_get_info_by_fd),
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
                                DLSYM_ARG(bpf_program__set_autoload),
                                DLSYM_ARG(libbpf_get_error),
                                DLSYM_ARG(libbpf_set_print),
                                DLSYM_ARG(ring_buffer__epoll_fd),
                                DLSYM_ARG(ring_buffer__free),
                                DLSYM_ARG(ring_buffer__new),
                                DLSYM_ARG(ring_buffer__poll));
                if (r >= 0)
                        break;
        }
        REENABLE_WARNING;
        if (r < 0)
                return cached = log_full_errno(in_initrd() ? LOG_DEBUG : log_level, r,
                                               "Neither libbpf.so.1 nor libbpf.so.0 are installed, cgroup BPF features disabled.");

        /* Version-specific symbols: bpf_create_map exists only in libbpf < 1.0; bpf_map_create and
         * bpf_object__next_map only in 0.7+. bpf_token_create only in 1.5+. Unresolved prototypes keep
         * their initializers (NULL, or a fallback returning -ENOSYS for bpf_token_create). */
        DLSYM_OPTIONAL(bpf_dl, bpf_create_map);
        DLSYM_OPTIONAL(bpf_dl, bpf_map_create);
        DLSYM_OPTIONAL(bpf_dl, bpf_object__next_map);
        DLSYM_OPTIONAL(bpf_dl, bpf_token_create);

        /* We set the print helper unconditionally. Otherwise libbpf will emit not useful log messages. */
        (void) sym_libbpf_set_print(bpf_print_func);

        return 1;
#else
        return log_once_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libbpf support is not compiled in, cgroup BPF features disabled.");
#endif
}

#if HAVE_LIBBPF
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
#endif
