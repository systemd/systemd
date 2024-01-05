/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "strv.h"
#include "time-util.h"

#define SNDBUF_SIZE (8*1024*1024)

static void unsetenv_all(bool unset_environment) {
        if (!unset_environment)
                return;

        assert_se(unsetenv("LISTEN_PID") == 0);
        assert_se(unsetenv("LISTEN_FDS") == 0);
        assert_se(unsetenv("LISTEN_FDNAMES") == 0);
}

_public_ int sd_listen_fds(int unset_environment) {
        const char *e;
        int n, r;
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

        for (int fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
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
                n_names = strv_split_full(&l, e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
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

                return stat_inode_same(&st_path, &st_fd);
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
                        return stat_inode_same(&st_path, &st_fd);
                else if (S_ISCHR(st_fd.st_mode) && S_ISCHR(st_path.st_mode))
                        return st_path.st_rdev == st_fd.st_rdev;
                else
                        return 0;
        }

        return 1;
}

static int is_socket_internal(int fd, int type, int listening) {
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

        r = is_socket_internal(fd, type, listening);
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

        r = is_socket_internal(fd, type, listening);
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

                r = sockaddr_port(&sockaddr, &sa_port);
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

        r = is_socket_internal(fd, type, listening);
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

        r = is_socket_internal(fd, type, listening);
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
                _cleanup_free_ char *fpath = NULL;
                struct stat a, b;

                assert_return(path_is_absolute(path), -EINVAL);

                if (fstat(fd, &a) < 0)
                        return -errno;

                fpath = path_join("/dev/mqueue", path);
                if (!fpath)
                        return -ENOMEM;

                if (stat(fpath, &b) < 0)
                        return -errno;

                if (!stat_inode_same(&a, &b))
                        return 0;
        }

        return 1;
}

static int vsock_bind_privileged_port(int fd) {
        union sockaddr_union sa = {
                .vm.svm_family = AF_VSOCK,
                .vm.svm_cid = VMADDR_CID_ANY,
                .vm.svm_port = 1023,
        };
        int r;

        assert(fd >= 0);

        do
                r = RET_NERRNO(bind(fd, &sa.sa, sizeof(sa.vm)));
        while (r == -EADDRINUSE && --sa.vm.svm_port > 0);

        return r;
}

static int pid_notify_with_fds_internal(
                pid_t pid,
                const char *state,
                const int *fds,
                unsigned n_fds) {
        SocketAddress address;
        struct iovec iovec;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_name = &address.sockaddr,
        };
        _cleanup_close_ int fd = -EBADF;
        struct cmsghdr *cmsg = NULL;
        const char *e;
        bool send_ucred;
        ssize_t n;
        int type, r;

        if (!state)
                return -EINVAL;

        if (n_fds > 0 && !fds)
                return -EINVAL;

        e = getenv("NOTIFY_SOCKET");
        if (!e)
                return 0;

        /* Allow AF_UNIX and AF_VSOCK, reject the rest. */
        r = socket_address_parse_unix(&address, e);
        if (r == -EPROTO)
                r = socket_address_parse_vsock(&address, e);
        if (r < 0)
                return r;
        msghdr.msg_namelen = address.size;

        /* If we didn't get an address (which is a normal pattern when specifying VSOCK tuples) error out,
         * we always require a specific CID. */
        if (address.sockaddr.vm.svm_family == AF_VSOCK && address.sockaddr.vm.svm_cid == VMADDR_CID_ANY)
                return -EINVAL;

        type = address.type == 0 ? SOCK_DGRAM : address.type;

        /* At the time of writing QEMU does not yet support AF_VSOCK + SOCK_DGRAM and returns
         * ENODEV. Fallback to SOCK_SEQPACKET in that case. */
        fd = socket(address.sockaddr.sa.sa_family, type|SOCK_CLOEXEC, 0);
        if (fd < 0) {
                if (!(ERRNO_IS_NOT_SUPPORTED(errno) || errno == ENODEV) || address.sockaddr.sa.sa_family != AF_VSOCK || address.type > 0)
                        return log_debug_errno(errno, "Failed to open %s notify socket to '%s': %m", socket_address_type_to_string(type), e);

                type = SOCK_SEQPACKET;
                fd = socket(address.sockaddr.sa.sa_family, type|SOCK_CLOEXEC, 0);
                if (fd < 0 && ERRNO_IS_NOT_SUPPORTED(errno)) {
                        type = SOCK_STREAM;
                        fd = socket(address.sockaddr.sa.sa_family, type|SOCK_CLOEXEC, 0);
                }
                if (fd < 0)
                        return log_debug_errno(errno, "Failed to open %s socket to '%s': %m", socket_address_type_to_string(type), e);
        }

        if (address.sockaddr.sa.sa_family == AF_VSOCK) {
                r = vsock_bind_privileged_port(fd);
                if (r < 0 && !ERRNO_IS_PRIVILEGE(r))
                        return log_debug_errno(r, "Failed to bind socket to privileged port: %m");
        }

        if (IN_SET(type, SOCK_STREAM, SOCK_SEQPACKET)) {
                if (connect(fd, &address.sockaddr.sa, address.size) < 0)
                        return log_debug_errno(errno, "Failed to connect socket to '%s': %m", e);

                msghdr.msg_name = NULL;
                msghdr.msg_namelen = 0;
        }

        (void) fd_inc_sndbuf(fd, SNDBUF_SIZE);

        iovec = IOVEC_MAKE_STRING(state);

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

                        ucred = CMSG_TYPED_DATA(cmsg, struct ucred);
                        ucred->pid = pid != 0 ? pid : getpid_cached();
                        ucred->uid = getuid();
                        ucred->gid = getgid();
                }
        }

        do {
                /* First try with fake ucred data, as requested */
                n = sendmsg(fd, &msghdr, MSG_NOSIGNAL);
                if (n < 0) {
                        if (!send_ucred)
                                return log_debug_errno(errno, "Failed to send notify message to '%s': %m", e);

                        /* If that failed, try with our own ucred instead */
                        msghdr.msg_controllen -= CMSG_SPACE(sizeof(struct ucred));
                        if (msghdr.msg_controllen == 0)
                                msghdr.msg_control = NULL;

                        n = 0;
                        send_ucred = false;
                } else {
                        /* Unless we're using SOCK_STREAM, we expect to write all the contents immediately. */
                        if (type != SOCK_STREAM && (size_t) n < iovec_total_size(msghdr.msg_iov, msghdr.msg_iovlen))
                                return -EIO;

                        /* Make sure we only send fds and ucred once, even if we're using SOCK_STREAM. */
                        msghdr.msg_control = NULL;
                        msghdr.msg_controllen = 0;
                }
        } while (!iovec_increment(msghdr.msg_iov, msghdr.msg_iovlen, n));

        return 1;
}

_public_ int sd_pid_notify_with_fds(
                pid_t pid,
                int unset_environment,
                const char *state,
                const int *fds,
                unsigned n_fds) {

        int r;

        r = pid_notify_with_fds_internal(pid, state, fds, n_fds);

        if (unset_environment)
                assert_se(unsetenv("NOTIFY_SOCKET") == 0);

        return r;
}

_public_ int sd_pid_notify_barrier(pid_t pid, int unset_environment, uint64_t timeout) {
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        int r;

        if (pipe2(pipe_fd, O_CLOEXEC) < 0)
                return -errno;

        r = sd_pid_notify_with_fds(pid, unset_environment, "BARRIER=1", &pipe_fd[1], 1);
        if (r <= 0)
                return r;

        pipe_fd[1] = safe_close(pipe_fd[1]);

        r = fd_wait_for_event(pipe_fd[0], 0 /* POLLHUP is implicit */, timeout);
        if (r < 0)
                return r;
        if (r == 0)
                return -ETIMEDOUT;

        return 1;
}

_public_ int sd_notify_barrier(int unset_environment, uint64_t timeout) {
        return sd_pid_notify_barrier(0, unset_environment, timeout);
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

_public_ int sd_pid_notifyf_with_fds(
                pid_t pid,
                int unset_environment,
                const int *fds, size_t n_fds,
                const char *format, ...) {

        _cleanup_free_ char *p = NULL;
        int r;

        /* Paranoia check: we traditionally used 'unsigned' as array size, but we nowadays more correctly use
         * 'size_t'. sd_pid_notifyf_with_fds() and sd_pid_notify_with_fds() are from different eras, hence
         * differ in this. Let's catch resulting incompatibilites early, even though they are pretty much
         * theoretic only */
        if (n_fds > UINT_MAX)
                return -E2BIG;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0 || !p)
                        return -ENOMEM;
        }

        return sd_pid_notify_with_fds(pid, unset_environment, p, fds, n_fds);
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
        if (!timestamp_is_set(u)) {
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
                assert_se(unsetenv("WATCHDOG_USEC") == 0);
        if (unset_environment && p)
                assert_se(unsetenv("WATCHDOG_PID") == 0);

        return r;
}
