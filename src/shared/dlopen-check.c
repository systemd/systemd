/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "apparmor-util.h"
#include "blkid-util.h"
#include "dlopen-check.h"
#include "libmount-util.h"
#include "log.h"
#include "pam-util.h"
#include "seccomp-util.h"
#include "selinux-util.h"

int dlopen_check(void) {
        /* Libraries without which the system is unusable or services run without proper security policy. */
        static const struct {
                const char *feature;
                int (*dlopen)(int log_level);
                bool enabled;
        } table[] = {
                { "apparmor", dlopen_libapparmor, HAVE_APPARMOR },
                { "blkid",    dlopen_libblkid,    HAVE_BLKID    },
                { "mount",    dlopen_libmount,    HAVE_LIBMOUNT },
                { "pam",      dlopen_libpam,      HAVE_PAM      },
                { "seccomp",  dlopen_libseccomp,  HAVE_SECCOMP  },
                { "selinux",  dlopen_libselinux,  HAVE_SELINUX  },
        };

        size_t n_tested = 0, n_missing = 0;
        int r;

        FOREACH_ELEMENT(i, table) {
                /* The helpers return EOPNOTSUPP for both compiled out and missing libraries. */
                if (!i->enabled) {
                        log_debug("Support for '%s' is not compiled in, skipping.", i->feature);
                        continue;
                }

                n_tested++;

                r = i->dlopen(LOG_ERR);
                if (r < 0) {
                        log_error("Support for '%s' is compiled in, but shared library could not be loaded.",
                                 i->feature);
                        n_missing++;
                        continue;
                }

                log_debug("Support for '%s' is available.", i->feature);
        }

        if (n_missing > 0)
                return log_error_errno(SYNTHETIC_ERRNO(ELIBACC),
                                       "%zu of %zu tested shared libraries could not be loaded.",
                                       n_missing, n_tested);

        log_debug("All %zu tested shared libraries are available.", n_tested);
        return 0;
}
