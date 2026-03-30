/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/liveupdate.h>
#include <sys/ioctl.h>

#include "errno-util.h"
#include "fd-util.h"
#include "luo-util.h"
#include "string-util.h"

/* Kernel API defined at https://docs.kernel.org/userspace-api/liveupdate.html The /dev/liveupdate is a
 * single-owner singleton, only a single process at any given time can open it. Callers can create named
 * "sessions", and then add FDs to them. The session name can be used to retrieve the session after reboot.
 * To identify an FD, a 64bit token (what we would call an 'index' in our codebase) is passed in, and the
 * caller is responsible for coming up with the token and tracking them. */

int luo_open_device(void) {
        return RET_NERRNO(open("/dev/liveupdate", O_RDWR|O_CLOEXEC));
}

int luo_create_session(int device_fd, const char *name) {
        struct liveupdate_ioctl_create_session args = {
                .size = sizeof(args),
                .fd = -EBADF,
        };

        assert(device_fd >= 0);
        assert(name);

        if (strlen(name) >= sizeof(args.name))
                return -ENAMETOOLONG;

        strncpy_exact((char *) args.name, name, sizeof(args.name));

        if (ioctl(device_fd, LIVEUPDATE_IOCTL_CREATE_SESSION, &args) < 0)
                return -errno;

        return args.fd;
}

int luo_retrieve_session(int device_fd, const char *name) {
        struct liveupdate_ioctl_retrieve_session args = {
                .size = sizeof(args),
                .fd = -EBADF,
        };

        assert(device_fd >= 0);
        assert(name);

        if (strlen(name) >= sizeof(args.name))
                return -ENAMETOOLONG;

        strncpy_exact((char *) args.name, name, sizeof(args.name));

        if (ioctl(device_fd, LIVEUPDATE_IOCTL_RETRIEVE_SESSION, &args) < 0)
                return -errno;

        return args.fd;
}

int luo_session_preserve_fd(int session_fd, int fd, uint64_t token) {
        struct liveupdate_session_preserve_fd args = {
                .size = sizeof(args),
                .fd = fd,
                .token = token,
        };

        assert(session_fd >= 0);
        assert(fd >= 0);

        return RET_NERRNO(ioctl(session_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &args));
}

int luo_session_retrieve_fd(int session_fd, uint64_t token) {
        struct liveupdate_session_retrieve_fd args = {
                .size = sizeof(args),
                .fd = -EBADF,
                .token = token,
        };
        int r;

        assert(session_fd >= 0);

        if (ioctl(session_fd, LIVEUPDATE_SESSION_RETRIEVE_FD, &args) < 0)
                return -errno;

        r = fd_cloexec(args.fd, true);
        if (r < 0) {
                safe_close(args.fd);
                return r;
        }

        return args.fd;
}

int luo_session_finish(int session_fd) {
        struct liveupdate_session_finish args = {
                .size = sizeof(args),
        };

        assert(session_fd >= 0);

        return RET_NERRNO(ioctl(session_fd, LIVEUPDATE_SESSION_FINISH, &args));
}
