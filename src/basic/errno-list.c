/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errno-list.h"

static const struct errno_name* lookup_errno(register const char *str,
                                             register GPERF_LEN_TYPE len);

#include "errno-from-name.inc"

int errno_from_name(const char *name) {
        const struct errno_name *sc;

        assert(name);

        sc = lookup_errno(name, strlen(name));
        if (!sc)
                return -EINVAL;

        assert(sc->id > 0);
        return sc->id;
}

#ifdef __GLIBC__
#include "errno-to-name.inc"

static const char *(*strerrorname_np_func)(int);

__attribute__((constructor)) static void strerrorname_np_func_init(void) {
        void *p = dlsym(RTLD_DEFAULT, "strerrorname_np");
        __asm__ volatile("" ::: "memory");
        strerrorname_np_func = (const char *(*)(int)) p;
}

const char* errno_name_no_fallback(int id) {
        if (id == 0) /* To stay in line with our implementation below.  */
                return NULL;

        id = ABS(id);

        if (strerrorname_np_func) {
                const char *n = strerrorname_np_func(id);
                if (n)
                        return n;
        }

        if ((size_t) id >= ELEMENTSOF(errno_names))
                return NULL;

        return errno_names[id];
}
#else
#  include "errno-to-name.inc"

const char* errno_name_no_fallback(int id) {
        if (id < 0)
                id = -id;

        if ((size_t) id >= ELEMENTSOF(errno_names))
                return NULL;

        return errno_names[id];
}
#endif

const char* errno_name(int id, char buf[static ERRNO_NAME_BUF_LEN]) {
        const char *a = errno_name_no_fallback(id);
        if (a)
                return a;
        snprintf(buf, ERRNO_NAME_BUF_LEN, "%d", abs(id));
        return buf;
}
