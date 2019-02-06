/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "strv.h"
#include "util.h"

#define SNDBUF_SIZE (8*1024*1024)

static void unsetenv_all(bool unset_environment) {

        if (!unset_environment)
                return;

        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
}

_public_ int sd_listen_fds(int unset_environment) {
        const char *e;
        int n, r, fd;
        pid_t pid;

        e = getenv("LISTEN_PID");
        if (!e) {
                r = 0;
                goto finish;
        }

        r = parse_pid(e, &pid);
        if (r < 0)
                goto finish;

        /* Is this for us? */
        if (getpid_cached() != pid) {
                r = 0;
                goto finish;
        }

        e = getenv("LISTEN_FDS");
        if (!e) {
                r = 0;
                goto finish;
        }

        r = safe_atoi(e, &n);
        if (r < 0)
                goto finish;

        assert_cc(SD_LISTEN_FDS_START < INT_MAX);
        if (n <= 0 || n > INT_MAX - SD_LISTEN_FDS_START) {
                r = -EINVAL;
                goto finish;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd ++) {
                r = fd_cloexec(fd, true);
                if (r < 0)
                        goto finish;
        }

        r = n;

finish:
        unsetenv_all(unset_environment);
        return r;
}

_public_ int sd_listen_fds_with_names(int unset_environment, char ***names) {
        _cleanup_strv_free_ char **l = NULL;
        bool have_names;
        int n_names = 0, n_fds;
        const char *e;
        int r;

        if (!names)
                return sd_listen_fds(unset_environment);

        e = getenv("LISTEN_FDNAMES");
        if (e) {
                n_names = strv_split_extract(&l, e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (n_names < 0) {
                        unsetenv_all(unset_environment);
                        return n_names;
                }

                have_names = true;
        } else
                have_names = false;

        n_fds = sd_listen_fds(unset_environment);
        if (n_fds <= 0)
                return n_fds;

        if (have_names) {
                if (n_names != n_fds)
                        return -EINVAL;
        } else {
                r = strv_extend_n(&l, "unknown", n_fds);
                if (r < 0)
                        return r;
        }

        *names = TAKE_PTR(l);

        return n_fds;
}

_public_ int sd_is_fifo(int fd, const char *path) {
        struct stat st_fd;

        assert_return(fd >= 0, -EBADF);

        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISFIFO(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

                if (stat(path, &st_path) < 0) {

                        if (IN_SET(errno, ENOENT, ENOTDIR))
                                return 0;

                        return -errno;
                }

                return
                        st_path.st_dev == st_fd.st_dev &&
                        st_path.st_ino == st_fd.st_ino;
        }

        return 1;
}

_public_ int sd_is_special(int fd, const char *path) {
        struct stat st_fd;

        assert_return(fd >= 0, -EBADF);

        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISREG(st_fd.st_mode) && !S_ISCHR(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

                if (stat(path, &st_path) < 0) {

                        if (IN_SET(errno, ENOENT, ENOTDIR))
                                return 0;

                        return -errno;
                }

                if (S_ISREG(st_fd.st_mode) && S_ISREG(st_path.st_mode))
                        return
                                st_path.st_dev == st_fd.st_dev &&
                                st_path.st_ino == st_fd.st_ino;
                else if (S_ISCHR(st_fd.st_mode) && S_ISCHR(st_path.st_mode))
                        return st_path.st_rdev == st_fd.st_rdev;
                else
                        return 0;
        }

        return 1;
}

static int sd_is_socket_internal(int fd, int type, int listening) {
        struct stat st_fd;

        assert_return(fd >= 0, -EBADF);
        assert_return(type >= 0, -EINVAL);

        if (fstat(fd, &st_fd) < 0)
                return -errno;

        if (!S_ISSOCK(st_fd.st_mode))
                return 0;

        if (type != 0) {
                int other_type = 0;
                socklen_t l = sizeof(other_type);

                if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &other_type, &l) < 0)
                        return -errno;

                if (l != sizeof(other_type))
                        return -EINVAL;

                if (other_type != type)
                        return 0;
        }

        if (listening >= 0) {
                int accepting = 0;
                socklen_t l = sizeof(accepting);

                if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &l) < 0)
                        return -errno;

                if (l != sizeof(accepting))
                        return -EINVAL;

                if (!accepting != !listening)
                        return 0;
        }

        return 1;
}

_public_ int sd_is_socket(int fd, int family, int type, int listening) {
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(family >= 0, -EINVAL);

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (family > 0) {
                union sockaddr_union sockaddr = {};
                socklen_t l = sizeof(sockaddr);

                if (getsockname(fd, &sockaddr.sa, &l) < 0)
                        return -errno;

                if (l < sizeof(sa_family_t))
                        return -EINVAL;

                return sockaddr.sa.sa_family == family;
        }

        return 1;
}

_public_ int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port) {
        union sockaddr_union sockaddr = {};
        socklen_t l = sizeof(sockaddr);
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(IN_SET(family, 0, AF_INET, AF_INET6), -EINVAL);

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (getsockname(fd, &sockaddr.sa, &l) < 0)
                return -errno;

        if (l < sizeof(sa_family_t))
                return -EINVAL;

        if (!IN_SET(sockaddr.sa.sa_family, AF_INET, AF_INET6))
                return 0;

        if (family != 0)
                if (sockaddr.sa.sa_family != family)
                        return 0;

        if (port > 0) {
                unsigned sa_port;

                r = sockaddr_port(&sockaddr.sa, &sa_port);
                if (r < 0)
                        return r;

                return port == sa_port;
        }

        return 1;
}

_public_ int sd_is_socket_sockaddr(int fd, int type, const struct sockaddr* addr, unsigned addr_len, int listening) {
        union sockaddr_union sockaddr = {};
        socklen_t l = sizeof(sockaddr);
        int r;

        assert_return(fd >= 0, -EBADF);
        assert_return(addr, -EINVAL);
        assert_return(addr_len >= sizeof(sa_family_t), -ENOBUFS);
        assert_return(IN_SET(addr->sa_family, AF_INET, AF_INET6), -EPFNOSUPPORT);

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (getsockname(fd, &sockaddr.sa, &l) < 0)
                return -errno;

        if (l < sizeof(sa_family_t))
                return -EINVAL;

        if (sockaddr.sa.sa_family != addr->sa_family)
                return 0;

        if (sockaddr.sa.sa_family == AF_INET) {
                const struct sockaddr_in *in = (const struct sockaddr_in *) addr;

                if (l < sizeof(struct sockaddr_in) || addr_len < sizeof(struct sockaddr_in))
                        return -EINVAL;

                if (in->sin_port != 0 &&
                    sockaddr.in.sin_port != in->sin_port)
                        return false;

                return sockaddr.in.sin_addr.s_addr == in->sin_addr.s_addr;

        } else {
                const struct sockaddr_in6 *in = (const struct sockaddr_in6 *) addr;

                if (l < sizeof(struct sockaddr_in6) || addr_len < sizeof(struct sockaddr_in6))
                        return -EINVAL;

                if (in->sin6_port != 0 &&
                    sockaddr.in6.sin6_port != in->sin6_port)
                        return false;

                if (in->sin6_flowinfo != 0 &&
                    sockaddr.in6.sin6_flowinfo != in->sin6_flowinfo)
                        return false;

                if (in->sin6_scope_id != 0 &&
                    sockaddr.in6.sin6_scope_id != in->sin6_scope_id)
                        return false;

                return memcmp(sockaddr.in6.sin6_addr.s6_addr, in->sin6_addr.s6_addr,
                              sizeof(in->sin6_addr.s6_addr)) == 0;
        }
}

_public_ int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) {
        union sockaddr_union sockaddr = {};
        socklen_t l = sizeof(sockaddr);
        int r;

        assert_return(fd >= 0, -EBADF);

        r = sd_is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (getsockname(fd, &sockaddr.sa, &l) < 0)
                return -errno;

        if (l < sizeof(sa_family_t))
                return -EINVAL;

        if (sockaddr.sa.sa_family != AF_UNIX)
                return 0;

        if (path) {
                if (length == 0)
                        length = strlen(path);

                if (length == 0)
                        /* Unnamed socket */
                        return l == offsetof(struct sockaddr_un, sun_path);

                if (path[0])
                        /* Normal path socket */
                        return
                                (l >= offsetof(struct sockaddr_un, sun_path) + length + 1) &&
                                memcmp(path, sockaddr.un.sun_path, length+1) == 0;
                else
                        /* Abstract namespace socket */
                        return
                                (l == offsetof(struct sockaddr_un, sun_path) + length) &&
                                memcmp(path, sockaddr.un.sun_path, length) == 0;
        }

        return 1;
}

_public_ int sd_is_mq(int fd, const char *path) {
        struct mq_attr attr;

        /* Check that the fd is valid */
        assert_return(fcntl(fd, F_GETFD) >= 0, -errno);

        if (mq_getattr(fd, &attr) < 0) {
                if (errno == EBADF)
                        /* A non-mq fd (or an invalid one, but we ruled that out above) */
                        return 0;
                return -errno;
        }

        if (path) {
                char fpath[PATH_MAX];
                struct stat a, b;

                assert_return(path_is_absolute(path), -EINVAL);

                if (fstat(fd, &a) < 0)
                        return -errno;

                strncpy(stpcpy(fpath, "/dev/mqueue"), path, sizeof(fpath) - 12);
                fpath[sizeof(fpath)-1] = 0;

                if (stat(fpath, &b) < 0)
                        return -errno;

                if (a.st_dev != b.st_dev ||
                    a.st_ino != b.st_ino)
                        return 0;
        }

        return 1;
}

_public_ int sd_pid_notify_with_fds(
                pid_t pid,
                int unset_environment,
                const char *state,
                const int *fds,
                unsigned n_fds) {

        union sockaddr_union sockaddr = {};
        struct iovec iovec;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_name = &sockaddr,
        };
        _cleanup_close_ int fd = -1;
        struct cmsghdr *cmsg = NULL;
        const char *e;
        bool send_ucred;
        int r, salen;

        if (!state) {
                r = -EINVAL;
                goto finish;
        }

        if (n_fds > 0 && !fds) {
                r = -EINVAL;
                goto finish;
        }

        e = getenv("NOTIFY_SOCKET");
        if (!e)
                return 0;

        salen = sockaddr_un_set_path(&sockaddr.un, e);
        if (salen < 0) {
                r = salen;
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                r = -errno;
                goto finish;
        }

        (void) fd_inc_sndbuf(fd, SNDBUF_SIZE);

        iovec = IOVEC_MAKE_STRING(state);
        msghdr.msg_namelen = salen;

        send_ucred =
                (pid != 0 && pid != getpid_cached()) ||
                getuid() != geteuid() ||
                getgid() != getegid();

        if (n_fds > 0 || send_ucred) {
                /* CMSG_SPACE(0) may return value different than zero, which results in miscalculated controllen. */
                msghdr.msg_controllen =
                        (n_fds > 0 ? CMSG_SPACE(sizeof(int) * n_fds) : 0) +
                        (send_ucred ? CMSG_SPACE(sizeof(struct ucred)) : 0);

                msghdr.msg_control = alloca0(msghdr.msg_controllen);

                cmsg = CMSG_FIRSTHDR(&msghdr);
                if (n_fds > 0) {
                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_RIGHTS;
                        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);

                        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * n_fds);

                        if (send_ucred)
                                assert_se(cmsg = CMSG_NXTHDR(&msghdr, cmsg));
                }

                if (send_ucred) {
                        struct ucred *ucred;

                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_CREDENTIALS;
                        cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));

                        ucred = (struct ucred*) CMSG_DATA(cmsg);
                        ucred->pid = pid != 0 ? pid : getpid_cached();
                        ucred->uid = getuid();
                        ucred->gid = getgid();
                }
        }

        /* First try with fake ucred data, as requested */
        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) >= 0) {
                r = 1;
                goto finish;
        }

        /* If that failed, try with our own ucred instead */
        if (send_ucred) {
                msghdr.msg_controllen -= CMSG_SPACE(sizeof(struct ucred));
                if (msghdr.msg_controllen == 0)
                        msghdr.msg_control = NULL;

                if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) >= 0) {
                        r = 1;
                        goto finish;
                }
        }

        r = -errno;

finish:
        if (unset_environment)
                unsetenv("NOTIFY_SOCKET");

        return r;
}

_public_ int sd_pid_notify(pid_t pid, int unset_environment, const char *state) {
        return sd_pid_notify_with_fds(pid, unset_environment, state, NULL, 0);
}

_public_ int sd_notify(int unset_environment, const char *state) {
        return sd_pid_notify_with_fds(0, unset_environment, state, NULL, 0);
}

_public_ int sd_pid_notifyf(pid_t pid, int unset_environment, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0 || !p)
                        return -ENOMEM;
        }

        return sd_pid_notify(pid, unset_environment, p);
}

_public_ int sd_notifyf(int unset_environment, const char *format, ...) {
        _cleanup_free_ char *p = NULL;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0 || !p)
                        return -ENOMEM;
        }

        return sd_pid_notify(0, unset_environment, p);
}

_public_ int sd_booted(void) {
        /* We test whether the runtime unit file directory has been
         * created. This takes place in mount-setup.c, so is
         * guaranteed to happen very early during boot. */

        if (laccess("/run/systemd/system/", F_OK) >= 0)
                return true;

        if (errno == ENOENT)
                return false;

        return -errno;
}

_public_ int sd_watchdog_enabled(int unset_environment, uint64_t *usec) {
        const char *s, *p = ""; /* p is set to dummy value to do unsetting */
        uint64_t u;
        int r = 0;

        s = getenv("WATCHDOG_USEC");
        if (!s)
                goto finish;

        r = safe_atou64(s, &u);
        if (r < 0)
                goto finish;
        if (u <= 0 || u >= USEC_INFINITY) {
                r = -EINVAL;
                goto finish;
        }

        p = getenv("WATCHDOG_PID");
        if (p) {
                pid_t pid;

                r = parse_pid(p, &pid);
                if (r < 0)
                        goto finish;

                /* Is this for us? */
                if (getpid_cached() != pid) {
                        r = 0;
                        goto finish;
                }
        }

        if (usec)
                *usec = u;

        r = 1;

finish:
        if (unset_environment && s)
                unsetenv("WATCHDOG_USEC");
        if (unset_environment && p)
                unsetenv("WATCHDOG_PID");

        return r;
}
