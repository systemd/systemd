/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "main-func.h"
#include "path-util.h"
#include "vpick.h"

static int process_hierarchy(
                const char *toplevel_path,
                const char *inode_path,
                int inode_fd,
                mode_t inode_mode,
                const char *inode_version,
                Architecture inode_architecture,
                const char *mountpoint_path,
                int mountpoint_fd,
                const char *target_path) {

        _cleanup_free_ char *full_inode_path = NULL, *full_target_path = NULL;

        full_inode_path = path_join(toplevel_path, inode_path);
        if (!full_inode_path)
                return log_oom();

        full_target_path = path_join(mountpoint_path, target_path);
        if (!full_target_path)
                return log_oom();

        log_info("Mounting %s → %s (version '%s', architecture '%s')",
                 full_inode_path, full_target_path,
                 strna(inode_version), strna(architecture_to_string(inode_architecture)));

        if (S_ISDIR(inode_mode)) {

                /* FIXME: bind mount */
        } else if (S_ISREG(inode_mode)) {

                /* FIXME: dissect + mount */

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EBADF), "Unexpected inode type, refusing.");

        return 0;
}

static int run(int argc, char *argv[]) {

        static const struct {
                const char *source;
                const char *target;
        } hierarchies[] = {
                { "root", "/"        },
                { "usr",  "/usr"     },
                { "var",  "/var"     },
                { "tmp",  "/var/tmp" },
                { "home", "/home"    },
                { "srv",  "/srv"     },
        };

        static const struct {
                const char *entrypoint_suffix;
                const char *search_suffix;
                mode_t search_mode;
        } parameters[] = {
                { "",     "",     S_IFDIR },
                { ".raw", "",     S_IFREG },
                { ".v",   "",     S_IFDIR },
                { ".v",   ".raw", S_IFREG },
        };

        _cleanup_free_ char *toplevel_path = NULL, *mountpoint_path = NULL;
        _cleanup_close_ int toplevel_fd = -EBADF, mountpoint_fd = -EBADF;
        int r;

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected number of arguments, refusing.");

        toplevel_path = strdup(argv[1]);
        if (!toplevel_path)
                return log_oom();

        path_simplify(toplevel_path);

        mountpoint_path = strdup(argv[2]);
        if (!mountpoint_path)
                return log_oom();

        path_simplify(mountpoint_path);

        toplevel_fd = open(toplevel_path, O_DIRECTORY|O_CLOEXEC);
        if (toplevel_fd < 0)
                return log_error_errno(errno, "Failed to open toplevel directory '%s': %m", toplevel_path);

        mountpoint_fd = open(mountpoint_path, O_DIRECTORY|O_CLOEXEC|O_PATH);
        if (mountpoint_fd < 0)
                return log_error_errno(errno, "Failed to open mount point directory '%s': %m", mountpoint_path);

        for (size_t i = 0; i < ELEMENTSOF(hierarchies); i++) {
                const typeof(hierarchies[i])* h = hierarchies + i;

                for (size_t j = 0; j < ELEMENTSOF(parameters); j++) {
                        _cleanup_free_ char *name = NULL, *inode_path = NULL, *inode_version = NULL;
                        Architecture inode_architecture = _ARCHITECTURE_INVALID;
                        const typeof(parameters[j])* p = parameters + j;
                        _cleanup_close_ int inode_fd = -1;
                        mode_t inode_mode = MODE_INVALID;

                        name = strjoin(h->source, p->entrypoint_suffix);
                        if (!name)
                                return log_oom();

                        r = path_pick(toplevel_path,
                                      toplevel_fd,
                                      name,
                                      p->search_mode,
                                      /* search_basename= */ NULL,
                                      /* search_version= */ NULL,
                                      _ARCHITECTURE_INVALID,
                                      p->search_suffix,
                                      &inode_path,
                                      &inode_fd,
                                      &inode_mode,
                                      &inode_version,
                                      &inode_architecture);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to pick item for hierarchy '%s/%s' (search suffix '%s'), ignoring: %m", toplevel_path, name, p->search_suffix);
                                continue;
                        }
                        if (r == 0) {
                                log_debug("Didn't find any items for hierarchy '%s/%s' (search suffix '%s').", toplevel_path, name, p->search_suffix);
                                continue;
                        }

                        r = process_hierarchy(
                                        toplevel_path,
                                        inode_path,
                                        inode_fd,
                                        inode_mode,
                                        inode_version,
                                        inode_architecture,
                                        mountpoint_path,
                                        mountpoint_fd,
                                        h->target);
                        if (r < 0)
                                return r;

                        break;
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
