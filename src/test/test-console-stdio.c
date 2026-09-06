/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "terminal-util.h"
#include "tests.h"

/* Run only on a dedicated inactive VT in a disposable VM, for example with openvt --wait.
 * The caller must already own that VT. The test neither allocates nor disallocates a VT,
 * and the mount namespace isolates only the /dev/console path, not the VT itself. */
TEST_RET(make_console_stdio) {
        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        _cleanup_free_ char *tty = NULL, *path = NULL;
        _cleanup_close_ int tty_fd = -EBADF, log_fd = -EBADF;
        struct vt_stat state;
        int saved_mode, mode, q, r;

        if (secure_getenv_bool("SYSTEMD_TEST_CONSOLE") <= 0)
                return log_tests_skipped("Set SYSTEMD_TEST_CONSOLE=1 on a dedicated inactive VT.");
        if (geteuid() != 0 ||
            have_effective_cap(CAP_SYS_ADMIN) <= 0 ||
            have_effective_cap(CAP_SYS_TTY_CONFIG) <= 0)
                return log_tests_skipped("Requires CAP_SYS_ADMIN and CAP_SYS_TTY_CONFIG.");
        if (access("/dev/console", F_OK) < 0)
                return log_tests_skipped_errno(errno, "No console mount point");

        if (get_ctty(0, /* ret_devnr= */ NULL, &tty) < 0 || !tty_is_vc(tty))
                return log_tests_skipped("Not running on a virtual console.");
        path = ASSERT_NOT_NULL(path_join("/dev", tty));
        tty_fd = open_terminal(path, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (tty_fd < 0)
                return log_tests_skipped_errno(tty_fd, "Cannot open the controlling VT");
        if (ioctl(tty_fd, VT_GETSTATE, &state) < 0 || state.v_active == vtnr_from_tty(tty))
                return log_tests_skipped("Requires an inactive virtual console.");
        if (ioctl(tty_fd, KDGETMODE, &saved_mode) < 0)
                return log_tests_skipped_errno(errno, "Cannot read the console mode");
        log_fd = ASSERT_OK_ERRNO(fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3));

        /* Keep the parent in the owning session so a child failure cannot hang up the VT. */
        r = pidref_safe_fork(
                        "test-console-stdio",
                        FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        &child);
        if (r < 0 && ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped("Cannot create a private mount namespace.");
        ASSERT_OK(r);
        if (r == 0) {
                r = mount(path, "/dev/console", /* fstype= */ NULL, MS_BIND, /* data= */ NULL);
                if (r < 0 && ERRNO_IS_PRIVILEGE(errno))
                        _exit(EXIT_TEST_SKIP);
                ASSERT_OK_ERRNO(r);
                r = ioctl(tty_fd, KDSETMODE, KD_GRAPHICS);
                if (r < 0 && ERRNO_IS_PRIVILEGE(errno))
                        _exit(EXIT_TEST_SKIP);
                ASSERT_OK_ERRNO(r);

                r = make_console_stdio(/* switch_to_text= */ false);
                ASSERT_OK_ERRNO(dup2(log_fd, STDERR_FILENO));
                ASSERT_OK(r);
                ASSERT_OK_ERRNO(ioctl(STDIN_FILENO, KDGETMODE, &mode));
                ASSERT_EQ(mode, KD_GRAPHICS);

                r = make_console_stdio(/* switch_to_text= */ true);
                ASSERT_OK_ERRNO(dup2(log_fd, STDERR_FILENO));
                ASSERT_OK(r);
                ASSERT_OK_ERRNO(ioctl(STDIN_FILENO, KDGETMODE, &mode));
                ASSERT_EQ(mode, KD_TEXT);
                _exit(EXIT_SUCCESS);
        }

        r = pidref_wait_for_terminate_and_check("test-console-stdio", &child, WAIT_LOG);

        /* Restore even after a failed assertion in the child, before asserting in the parent. */
        q = RET_NERRNO(ioctl(tty_fd, KDGETMODE, &mode));
        if (q < 0 || mode != saved_mode)
                q = RET_NERRNO(ioctl(tty_fd, KDSETMODE, saved_mode));
        ASSERT_OK(q);
        if (r == EXIT_TEST_SKIP)
                return log_tests_skipped("Console setup is not permitted.");
        ASSERT_OK_ZERO(r);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN(LOG_INFO);
