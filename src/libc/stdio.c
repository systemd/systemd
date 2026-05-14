/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>

/* sscanf/fscanf are variadic, so they can't be handled by DEFINE_LIBC_PURE_SHIM (C has no way to
 * forward "..." to another variadic function). Instead, dlsym the va_list-taking sibling and
 * forward through it. __isoc99_v{s,f}scanf is what the glibc headers redirect plain v{s,f}scanf
 * to under __USE_ISOC99 (which is implied by _GNU_SOURCE), so resolving those names preserves
 * the exact C99 scanf semantics we'd otherwise get; they've been present since GLIBC_2.7. */

typedef int (*vsscanf_fn_t)(const char *str, const char *format, va_list ap);
typedef int (*vfscanf_fn_t)(FILE *stream, const char *format, va_list ap);

static void *resolve(void **cache, const char *name) {
        void *p = __atomic_load_n(cache, __ATOMIC_ACQUIRE);
        if (p == (void *) -1) {
                p = dlsym(RTLD_DEFAULT, name);
                __atomic_store_n(cache, p, __ATOMIC_RELEASE);
        }
        return p;
}

int sscanf_shim(const char *str, const char *format, ...) {
        static void *cache = (void *) -1;
        int r;

        vsscanf_fn_t fn = (vsscanf_fn_t) resolve(&cache, "__isoc99_vsscanf");
        va_list ap;
        va_start(ap, format);
         r = fn(str, format, ap);
        va_end(ap);
        return r;
}

int fscanf_shim(FILE *stream, const char *format, ...) {
        static void *cache = (void *) -1;
        int r;
        
        vfscanf_fn_t fn = (vfscanf_fn_t) resolve(&cache, "__isoc99_vfscanf");
        va_list ap;
        va_start(ap, format);
        r = fn(stream, format, ap);
        va_end(ap);
        return r;
}
