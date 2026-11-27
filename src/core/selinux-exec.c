/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* SELinux transition helper. Consumes a pending `setexeccon()` context on its
 * own `execve`, then re-execs the real command under normal policy transitions.
 * argv[1] = executable path, argv[2..] = original argv for the executable. */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[], char *envp[]) {
        if (argc < 3) {
                fputs("systemd-selinux-exec: missing executable path and argv.\n", stderr);
                return 1;
        }

        execve(argv[1], argv + 2, envp);
        fprintf(stderr, "systemd-selinux-exec: Failed to execute '%s': %m\n", argv[1]);
        return 203; /* EXIT_EXEC */
}
