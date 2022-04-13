/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

int parse_devnum(const char *s, dev_t *ret);

/* glibc and the Linux kernel have different ideas about the major/minor size. These calls will check whether the
 * specified major is valid by the Linux kernel's standards, not by glibc's. Linux has 20bits of minor, and 12 bits of
 * major space. See MINORBITS in linux/kdev_t.h in the kernel sources. (If you wonder why we define _y here, instead of
 * comparing directly >= 0: it's to trick out -Wtype-limits, which would otherwise complain if the type is unsigned, as
 * such a test would be pointless in such a case.) */

#define DEVICE_MAJOR_VALID(x)                                           \
        ({                                                              \
                typeof(x) _x = (x), _y = 0;                             \
                _x >= _y && _x < (UINT32_C(1) << 12);                   \
                                                                        \
        })

#define DEVICE_MINOR_VALID(x)                                           \
        ({                                                              \
                typeof(x) _x = (x), _y = 0;                             \
                _x >= _y && _x < (UINT32_C(1) << 20);                   \
        })

int device_path_make_major_minor(mode_t mode, dev_t devnum, char **ret);
int device_path_make_canonical(mode_t mode, dev_t devnum, char **ret);
int device_path_parse_major_minor(const char *path, mode_t *ret_mode, dev_t *ret_devnum);

static inline bool devnum_set_and_equal(dev_t a, dev_t b) {
        /* Returns true if a and b definitely refer to the same device. If either is zero, this means "don't
         * know" and we'll return false */
        return a == b && a != 0;
}
