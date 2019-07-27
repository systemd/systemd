/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
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

        const char *inaccessible[] = {
                "/home/lennart/projects",
                NULL
        };

        static const NamespaceInfo ns_info = {
                .private_dev = true,
                .protect_control_groups = true,
                .protect_kernel_tunables = true,
                .protect_kernel_modules = true,
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

        r = setup_namespace(root_directory,
                            NULL,
                            &ns_info,
                            (char **) writable,
                            (char **) readonly,
                            (char **) inaccessible,
                            NULL,
                            &(BindMount) { .source = (char*) "/usr/bin", .destination = (char*) "/etc/systemd", .read_only = true }, 1,
                            &(TemporaryFileSystem) { .path = (char*) "/var", .options = (char*) "ro" }, 1,
                            tmp_dir,
                            var_tmp_dir,
                            PROTECT_HOME_NO,
                            PROTECT_SYSTEM_NO,
                            0,
                            0,
                            NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to setup namespace: %m");

                log_info("Usage:\n"
                         "  sudo TEST_NS_PROJECTS=/home/lennart/projects ./test-ns\n"
                         "  sudo TEST_NS_CHROOT=/home/alban/debian-tree TEST_NS_PROJECTS=/home/alban/debian-tree/home/alban/Documents ./test-ns");

                return 1;
        }

        execl("/bin/sh", "/bin/sh", NULL);
        log_error_errno(errno, "execl(): %m");

        return 1;
}
