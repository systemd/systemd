/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ftw.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "capability-util.h"
#include "fileio.h"
#include "kmod-setup.h"
#include "macro.h"
#include "string-util.h"

#if HAVE_KMOD
#include <libkmod.h>
#include "module-util.h"

static void systemd_kmod_log(
                void *data,
                int priority,
                const char *file, int line,
                const char *fn,
                const char *format,
                va_list args) {

        /* library logging is enabled at debug only */
        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_DEBUG, 0, file, line, fn, format, args);
        REENABLE_WARNING;
}

static int has_virtio_rng_nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        _cleanup_free_ char *alias = NULL;
        int r;

        if ((FTW_D == tflag) && (ftwbuf->level > 2))
                return FTW_SKIP_SUBTREE;

        if (FTW_F != tflag)
                return FTW_CONTINUE;

        if (!endswith(fpath, "/modalias"))
                return FTW_CONTINUE;

        r = read_one_line_file(fpath, &alias);
        if (r < 0)
                return FTW_SKIP_SIBLINGS;

        if (startswith(alias, "pci:v00001AF4d00001005"))
                return FTW_STOP;

        if (startswith(alias, "pci:v00001AF4d00001044"))
                return FTW_STOP;

        return FTW_SKIP_SIBLINGS;
}

static bool has_virtio_rng(void) {
        return (nftw("/sys/devices/pci0000:00", has_virtio_rng_nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL) == FTW_STOP);
}
#endif

int kmod_setup(void) {
#if HAVE_KMOD

        static const struct {
                const char *module;
                const char *path;
                bool warn_if_unavailable:1;
                bool warn_if_module:1;
                bool (*condition_fn)(void);
        } kmod_table[] = {
                /* This one we need to load explicitly, since auto-loading on use doesn't work
                 * before udev created the ghost device nodes, and we need it earlier than that. */
                { "autofs4",   "/sys/class/misc/autofs",    true,   false,   NULL      },

                /* This one we need to load explicitly, since auto-loading of IPv6 is not done when
                 * we try to configure ::1 on the loopback device. */
                { "ipv6",      "/sys/module/ipv6",          false,  true,    NULL      },

                /* This should never be a module */
                { "unix",      "/proc/net/unix",            true,   true,    NULL      },

#if HAVE_LIBIPTC
                /* netfilter is needed by networkd, nspawn among others, and cannot be autoloaded */
                { "ip_tables", "/proc/net/ip_tables_names", false,  false,   NULL      },
#endif
                /* virtio_rng would be loaded by udev later, but real entropy might be needed very early */
                { "virtio_rng", NULL,                       false,  false,   has_virtio_rng },
        };
        _cleanup_(kmod_unrefp) struct kmod_ctx *ctx = NULL;
        unsigned i;

        if (have_effective_cap(CAP_SYS_MODULE) == 0)
                return 0;

        for (i = 0; i < ELEMENTSOF(kmod_table); i++) {
                if (kmod_table[i].path && access(kmod_table[i].path, F_OK) >= 0)
                        continue;

                if (kmod_table[i].condition_fn && !kmod_table[i].condition_fn())
                        continue;

                if (kmod_table[i].warn_if_module)
                        log_debug("Your kernel apparently lacks built-in %s support. Might be "
                                  "a good idea to compile it in. We'll now try to work around "
                                  "this by loading the module...", kmod_table[i].module);

                if (!ctx) {
                        ctx = kmod_new(NULL, NULL);
                        if (!ctx)
                                return log_oom();

                        kmod_set_log_fn(ctx, systemd_kmod_log, NULL);
                        kmod_load_resources(ctx);
                }

                (void) module_load_and_warn(ctx, kmod_table[i].module, kmod_table[i].warn_if_unavailable);
        }

#endif
        return 0;
}
