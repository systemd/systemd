/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* libbpf has been moving quickly.
 * They added new symbols in the 0.x versions and shortly after removed
 * deprecated symbols in 1.0.
 * We only need bpf_map_create and libbpf_probe_bpf_prog_type so we work
 * around the incompatibility here by:
 *  - redefining required types and macros for older libbpf that miss them
 *  - declaring both symbols, and looking for either depending on the libbpf
 *    so version we found
 *  - having helpers that automatically use the appropriate version behind the
 *    new API for easy cleanup later
 *
 * The advantage of doing this instead of only looking for the symbols declared at
 * compile time is that we can then load either the old or the new symbols at runtime
 * regardless of the version we were compiled with */

/* the 'bpf_map_create_opts__last_field' has been added with the struct and can be used
 * to check its presence */
#ifndef bpf_map_create_opts__last_field
struct bpf_map_create_opts {
        size_t sz;

        __u32 btf_fd;
        __u32 btf_key_type_id;
        __u32 btf_value_type_id;
        __u32 btf_vmlinux_value_type_id;

        int inner_map_fd;
        int map_flags;
        __u64 map_extra;

        int numa_node;
        int map_ifindex;
};
#endif

/* DECLARE_LIBBPF_OPTS was just renamed to LIBBPF_OPTS, we can rename it back */
#ifndef LIBBPF_OPTS
#define LIBBPF_OPTS DECLARE_LIBBPF_OPTS
#endif

/* new symbols available from 0.7.0.
 * We need the symbols here:
 *  - after bpf_map_create_opts struct has been defined for older libbpf
 *  - before the compat static inline helpers that use them.
 * When removing this file move these back to bpf-dlopen.h */
extern int (*sym_bpf_map_create)(enum bpf_map_type,  const char *, __u32, __u32, __u32, const struct bpf_map_create_opts *);
extern bool (*sym_libbpf_probe_bpf_prog_type)(enum bpf_prog_type, const void *);

/* compat symbols removed in libbpf 1.0 */
extern int (*sym_bpf_create_map)(enum bpf_map_type, int key_size, int value_size, int max_entries, __u32 map_flags);
extern bool (*sym_bpf_probe_prog_type)(enum bpf_prog_type, __u32);

/* helpers to use the available variant behind new API */
static inline int compat_bpf_map_create(enum bpf_map_type map_type,
                const char *map_name,
                __u32 key_size,
                __u32 value_size,
                __u32 max_entries,
                const struct bpf_map_create_opts *opts) {
        if (sym_bpf_map_create)
                return sym_bpf_map_create(map_type, map_name, key_size,
                                          value_size, max_entries, opts);

        return sym_bpf_create_map(map_type, key_size, value_size, max_entries,
                                  opts ? opts->map_flags : 0);
}

static inline int compat_libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts) {
        if (sym_libbpf_probe_bpf_prog_type)
                return sym_libbpf_probe_bpf_prog_type(prog_type, opts);

        return sym_bpf_probe_prog_type(prog_type, 0);
}
