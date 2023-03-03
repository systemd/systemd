/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "main-func.h"
#include "path-util.h"
#include "vpick.h"

static int run(int argc, char *argv[]) {

        static const struct {
                const char *target;
                const char *source;
        } images[] = {
                {
                        .source = "root",
                        .target = "/",
                },
                {
                        .source = "usr",
                        .target = "/usr",
                },
                {
                        .source = "var",
                        .target = "/var",
                },
                {
                        .source = "tmp",
                        .target = "/var/tmp",
                },
                {
                        .source = "home",
                        .target = "/home",
                },
                {
                        .source = "srv",
                        .target = "/srv",
                },
        };

        _cleanup_free_ char *toplevel_path = NULL;
        _cleanup_close_ int toplevel_fd = -1;
        int r;

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected number of arguments, refusing.");

        toplevel_path = strdup(argv[1]);
        if (!toplevel_path)
                return log_oom();

        path_simplify(toplevel_path);

        toplevel_fd = open(toplevel_path, O_DIRECTORY|O_CLOEXEC);
        if (toplevel_fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", toplevel_path);

        for (size_t i = 0; i < ELEMENTSOF(images); i++) {
                _cleanup_free_ char *inode_path = NULL, *inode_version = NULL;
                Architecture inode_architecture = _ARCHITECTURE_INVALID;
                _cleanup_close_ int inode_fd = -1;
                mode_t inode_mode = MODE_INVALID;

                r = image_pick(
                                toplevel_path,
                                toplevel_fd,
                                images[i].source,
                                /* version= */ NULL,
                                _ARCHITECTURE_INVALID,
                                &inode_path,
                                &inode_fd,
                                &inode_mode,
                                &inode_version,
                                &inode_architecture);
                if (r < 0)
                        continue;
                if (r == 0) {
                        printf("'%s' not found\n", images[i].source);
                        continue;
                }

                printf("%s/%s → %s\n", toplevel_path, inode_path, images[i].target);
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
