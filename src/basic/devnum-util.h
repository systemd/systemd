/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/sysmacros.h>

#include "forward.h"

int parse_devnum(const char *s, dev_t *ret);

#define DEVNUM_MAJOR_MAX ((UINT32_C(1) << 12) - 1U)
#define DEVNUM_MINOR_MAX ((UINT32_C(1) << 20) - 1U)

/* glibc and the Linux kernel have different ideas about the major/minor size. These calls will check whether the
 * specified major is valid by the Linux kernel's standards, not by glibc's. Linux has 20bits of minor, and 12 bits of
 * major space. See MINORBITS in linux/kdev_t.h in the kernel sources. (If you wonder why we define _y here, instead of
 * comparing directly >= 0: it's to trick out -Wtype-limits, which would otherwise complain if the type is unsigned, as
 * such a test would be pointless in such a case.) */

#define DEVICE_MAJOR_VALID(x)                                           \
        ({                                                              \
                typeof(x) _x = (x), _y = 0;                             \
                _x >= _y && _x <= DEVNUM_MAJOR_MAX;                     \
                                                                        \
        })

#define DEVICE_MINOR_VALID(x)                                           \
        ({                                                              \
                typeof(x) _x = (x), _y = 0;                             \
                _x >= _y && _x <= DEVNUM_MINOR_MAX;                     \
        })

int device_path_make_major_minor(mode_t mode, dev_t devnum, char **ret);
int device_path_make_inaccessible(mode_t mode, char **ret);
int device_path_make_canonical(mode_t mode, dev_t devnum, char **ret);
int device_path_parse_major_minor(const char *path, mode_t *ret_mode, dev_t *ret_devnum);

static inline bool devnum_set_and_equal(dev_t a, dev_t b) {
        /* Returns true if a and b definitely refer to the same device. If either is zero, this means "don't
         * know" and we'll return false */
        return a == b && a != 0;
}

/* Maximum string length for a major:minor string. (Note that DECIMAL_STR_MAX includes space for a trailing NUL) */
#define DEVNUM_STR_MAX (DECIMAL_STR_MAX(dev_t)-1+1+DECIMAL_STR_MAX(dev_t))

#define DEVNUM_FORMAT_STR "%u:%u"
#define DEVNUM_FORMAT_VAL(d) major(d), minor(d)

char *format_devnum(dev_t d, char buf[static DEVNUM_STR_MAX]);

#define FORMAT_DEVNUM(d) format_devnum((d), (char[DEVNUM_STR_MAX]) {})

static inline bool devnum_is_zero(dev_t d) {
        return major(d) == 0 && minor(d) == 0;
}

#define DEVNUM_TO_PTR(u) ((void*) (uintptr_t) (u))
#define PTR_TO_DEVNUM(p) ((dev_t) ((uintptr_t) (p)))
