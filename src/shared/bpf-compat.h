/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* libbpf has been moving quickly.
 * They added new symbols in the 0.x versions and shortly after removed
 * deprecated symbols in 1.0.
 * We only need bpf_map_create and libbpf_probe_bpf_prog_type so we work
 * around the incompatibility here by:
 *  - declaring both symbols, and looking for either depending on the libbpf
 *    so version we found
 *  - having helpers that automatically use the appropriate version behind the
 *    new API for easy cleanup later
 *
 * The advantage of doing this instead of only looking for the symbols declared at
 * compile time is that we can then load either the old or the new symbols at runtime
 * regardless of the version we were compiled with */

/* declare the struct for libbpf <= 0.6.0 -- it causes no harm on newer versions */
struct bpf_map_create_opts;

/* new symbols available from 0.7.0.
 * We need the symbols here:
 *  - after bpf_map_create_opts struct has been defined for older libbpf
 *  - before the compat static inline helpers that use them.
 * When removing this file move these back to bpf-dlopen.h */
extern int (*sym_bpf_map_create)(enum bpf_map_type,  const char *, __u32, __u32, __u32, const struct bpf_map_create_opts *);
extern int (*sym_libbpf_probe_bpf_prog_type)(enum bpf_prog_type, const void *);
extern struct bpf_map* (*sym_bpf_object__next_map)(const struct bpf_object *obj, const struct bpf_map *map);

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
                                  0 /* opts->map_flags, but opts is always NULL for us so skip build dependency on the type */);
}

static inline int compat_libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts) {
        if (sym_libbpf_probe_bpf_prog_type)
                return sym_libbpf_probe_bpf_prog_type(prog_type, opts);

        return sym_bpf_probe_prog_type(prog_type, 0);
}
