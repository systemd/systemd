/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "namespace.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        const char * const writable[] = {
                "/home",
                "-/home/lennart/projects/foobar", /* this should be masked automatically */
                NULL
        };

        const char * const readonly[] = {
                /* "/", */
                /* "/usr", */
                "/boot",
                "/lib",
                "/usr/lib",
                "-/lib64",
                "-/usr/lib64",
                NULL
        };

        const char * const exec[] = {
                "/lib",
                "/usr",
                "-/lib64",
                "-/usr/lib64",
                NULL
        };

        const char * const no_exec[] = {
                "/var",
                NULL
        };

        const char *inaccessible[] = {
                "/home/lennart/projects",
                NULL
        };

        static const BindMount bind_mount = {
                .source = (char*) "/usr/bin",
                .destination = (char*) "/etc/systemd",
                .read_only = true,
        };

        static const TemporaryFileSystem tmpfs = {
                .path = (char*) "/var",
                .options = (char*) "ro",
        };

        char *root_directory;
        char *projects_directory;
        int r;
        char tmp_dir[] = "/tmp/systemd-private-XXXXXX",
             var_tmp_dir[] = "/var/tmp/systemd-private-XXXXXX";

        test_setup_logging(LOG_DEBUG);

        assert_se(mkdtemp(tmp_dir));
        assert_se(mkdtemp(var_tmp_dir));

        root_directory = getenv("TEST_NS_CHROOT");
        projects_directory = getenv("TEST_NS_PROJECTS");

        if (projects_directory)
                inaccessible[0] = projects_directory;

        log_info("Inaccessible directory: '%s'", inaccessible[0]);
        if (root_directory)
                log_info("Chroot: '%s'", root_directory);
        else
                log_info("Not chrooted");

        _cleanup_(pinned_resource_done) PinnedResource pr = PINNED_RESOURCE_NULL;

        if (root_directory) {
                pr.directory_fd = open(root_directory, O_PATH|O_CLOEXEC|O_DIRECTORY);
                assert_se(pr.directory_fd >= 0);

                pr.directory = strdup(root_directory);
                assert_se(pr.directory);
        }

        NamespaceParameters p = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,

                .rootfs = &pr,

                .read_write_paths = (char**) writable,
                .read_only_paths = (char**) readonly,
                .inaccessible_paths = (char**) inaccessible,

                .exec_paths = (char**) exec,
                .no_exec_paths = (char**) no_exec,

                .tmp_dir = tmp_dir,
                .var_tmp_dir = var_tmp_dir,

                .bind_mounts = &bind_mount,
                .n_bind_mounts = 1,

                .temporary_filesystems = &tmpfs,
                .n_temporary_filesystems = 1,

                .private_dev = true,
                .protect_control_groups = true,
                .protect_kernel_tunables = true,
                .protect_kernel_modules = true,
                .protect_proc = PROTECT_PROC_NOACCESS,
                .proc_subset = PROC_SUBSET_PID,
        };

        r = setup_namespace(&p, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to set up namespace: %m");

                log_info("Usage:\n"
                         "  sudo TEST_NS_PROJECTS=/home/lennart/projects ./test-ns\n"
                         "  sudo TEST_NS_CHROOT=/home/alban/debian-tree TEST_NS_PROJECTS=/home/alban/debian-tree/home/alban/Documents ./test-ns");

                return 1;
        }

        execl("/bin/sh", "/bin/sh", NULL);
        log_error_errno(errno, "execl(): %m");

        return 1;
}
