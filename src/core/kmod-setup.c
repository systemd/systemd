/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "capability-util.h"
#include "fileio.h"
#include "kmod-setup.h"
#include "macro.h"
#include "recurse-dir.h"
#include "string-util.h"

#if HAVE_KMOD
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

static int has_virtio_rng_recurse_dir_cb(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        _cleanup_free_ char *alias = NULL;
        int r;

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (de->d_type != DT_REG)
                return RECURSE_DIR_CONTINUE;

        if (!streq(de->d_name, "modalias"))
                return RECURSE_DIR_CONTINUE;

        r = read_one_line_file(path, &alias);
        if (r < 0) {
                log_debug_errno(r, "Failed to read %s, ignoring: %m", path);
                return RECURSE_DIR_LEAVE_DIRECTORY;
        }

        if (startswith(alias, "pci:v00001AF4d00001005"))
                return 1;

        if (startswith(alias, "pci:v00001AF4d00001044"))
                return 1;

        return RECURSE_DIR_LEAVE_DIRECTORY;
}

static bool has_virtio_rng(void) {
        int r;

        r = recurse_dir_at(
                        AT_FDCWD,
                        "/sys/devices/pci0000:00",
                        /* statx_mask= */ 0,
                        /* n_depth_max= */ 2,
                        RECURSE_DIR_ENSURE_TYPE,
                        has_virtio_rng_recurse_dir_cb,
                        NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to determine whether host has virtio-rng device, ignoring: %m");

        return r > 0;
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
