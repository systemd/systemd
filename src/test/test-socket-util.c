/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <grp.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "async.h"
#include "escape.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fs-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

assert_cc(SUN_PATH_LEN == 108);

TEST(ifname_valid) {
        assert_se( ifname_valid("foo"));
        assert_se( ifname_valid("eth0"));

        assert_se(!ifname_valid("0"));
        assert_se(!ifname_valid("99"));
        assert_se( ifname_valid("a99"));
        assert_se( ifname_valid("99a"));

        assert_se(!ifname_valid(NULL));
        assert_se(!ifname_valid(""));
        assert_se(!ifname_valid(" "));
        assert_se(!ifname_valid(" foo"));
        assert_se(!ifname_valid("bar\n"));
        assert_se(!ifname_valid("."));
        assert_se(!ifname_valid(".."));
        assert_se(ifname_valid("foo.bar"));
        assert_se(!ifname_valid("x:y"));

        assert_se( ifname_valid_full("xxxxxxxxxxxxxxx", 0));
        assert_se(!ifname_valid_full("xxxxxxxxxxxxxxxx", 0));
        assert_se( ifname_valid_full("xxxxxxxxxxxxxxxx", IFNAME_VALID_ALTERNATIVE));
        assert_se( ifname_valid_full("xxxxxxxxxxxxxxxx", IFNAME_VALID_ALTERNATIVE));
        assert_se(!ifname_valid_full("999", IFNAME_VALID_ALTERNATIVE));
        assert_se( ifname_valid_full("999", IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC));
        assert_se(!ifname_valid_full("0", IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC));
}

static void test_socket_print_unix_one(const char *in, size_t len_in, const char *expected) {
        _cleanup_free_ char *out = NULL, *c = NULL;

        assert_se(len_in <= SUN_PATH_LEN);
        SocketAddress a = { .sockaddr = { .un = { .sun_family = AF_UNIX } },
                            .size = offsetof(struct sockaddr_un, sun_path) + len_in,
                            .type = SOCK_STREAM,
        };
        memcpy(a.sockaddr.un.sun_path, in, len_in);

        assert_se(socket_address_print(&a, &out) >= 0);
        assert_se(c = cescape(in));
        log_info("\"%s\" → \"%s\" (expect \"%s\")", in, out, expected);
        ASSERT_STREQ(out, expected);
}

TEST(socket_print_unix) {
        /* Some additional tests for abstract addresses which we don't parse */

        test_socket_print_unix_one("\0\0\0\0", 4, "@\\000\\000\\000");
        test_socket_print_unix_one("@abs", 5, "@abs");
        test_socket_print_unix_one("\n", 2, "\\n");
        test_socket_print_unix_one("", 1, "<unnamed>");
        test_socket_print_unix_one("\0", 1, "<unnamed>");
        test_socket_print_unix_one("\0_________________________there's 108 characters in this string_____________________________________________", 108,
                                   "@_________________________there\\'s 108 characters in this string_____________________________________________");
        test_socket_print_unix_one("////////////////////////////////////////////////////////////////////////////////////////////////////////////", 108,
                                   "////////////////////////////////////////////////////////////////////////////////////////////////////////////");
        test_socket_print_unix_one("\0\a\b\n\255", 6, "@\\a\\b\\n\\255\\000");
}

TEST(sockaddr_equal) {
        union sockaddr_union a = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htobe32(INADDR_ANY),
        };
        union sockaddr_union b = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htobe32(INADDR_ANY),
        };
        union sockaddr_union c = {
                .in.sin_family = AF_INET,
                .in.sin_port = 0,
                .in.sin_addr.s_addr = htobe32(1234),
        };
        union sockaddr_union d = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = 0,
                .in6.sin6_addr = IN6ADDR_ANY_INIT,
        };
        union sockaddr_union e = {
                .vm.svm_family = AF_VSOCK,
                .vm.svm_port = 0,
                .vm.svm_cid = VMADDR_CID_ANY,
        };

        assert_se(sockaddr_equal(&a, &a));
        assert_se(sockaddr_equal(&a, &b));
        assert_se(sockaddr_equal(&d, &d));
        assert_se(sockaddr_equal(&e, &e));
        assert_se(!sockaddr_equal(&a, &c));
        assert_se(!sockaddr_equal(&b, &c));
        assert_se(!sockaddr_equal(&a, &e));
}

TEST(sockaddr_un_len) {
        static const struct sockaddr_un fs = {
                .sun_family = AF_UNIX,
                .sun_path = "/foo/bar/waldo",
        };

        static const struct sockaddr_un abstract = {
                .sun_family = AF_UNIX,
                .sun_path = "\0foobar",
        };

        assert_se(SOCKADDR_UN_LEN(fs) == offsetof(struct sockaddr_un, sun_path) + strlen(fs.sun_path) + 1);
        assert_se(SOCKADDR_UN_LEN(abstract) == offsetof(struct sockaddr_un, sun_path) + 1 + strlen(abstract.sun_path + 1));
}

TEST(in_addr_is_multicast) {
        union in_addr_union a, b;
        int f;

        assert_se(in_addr_from_string_auto("192.168.3.11", &f, &a) >= 0);
        assert_se(in_addr_is_multicast(f, &a) == 0);

        assert_se(in_addr_from_string_auto("224.0.0.1", &f, &a) >= 0);
        assert_se(in_addr_is_multicast(f, &a) == 1);

        assert_se(in_addr_from_string_auto("FF01:0:0:0:0:0:0:1", &f, &b) >= 0);
        assert_se(in_addr_is_multicast(f, &b) == 1);

        assert_se(in_addr_from_string_auto("2001:db8::c:69b:aeff:fe53:743e", &f, &b) >= 0);
        assert_se(in_addr_is_multicast(f, &b) == 0);
}

TEST(getpeercred_getpeergroups) {
        int r;

        r = safe_fork("(getpeercred)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                static const gid_t gids[] = { 3, 4, 5, 6, 7 };
                gid_t *test_gids;
                size_t n_test_gids;
                uid_t test_uid;
                gid_t test_gid;
                struct ucred ucred;
                int pair[2] = EBADF_PAIR;

                if (geteuid() == 0 && !userns_has_single_user()) {
                        test_uid = 1;
                        test_gid = 2;
                        test_gids = (gid_t*) gids;
                        n_test_gids = ELEMENTSOF(gids);

                        assert_se(fully_set_uid_gid(test_uid, test_gid, test_gids, n_test_gids) >= 0);
                } else {
                        long ngroups_max;

                        test_uid = getuid();
                        test_gid = getgid();

                        ngroups_max = sysconf(_SC_NGROUPS_MAX);
                        assert_se(ngroups_max > 0);

                        test_gids = newa(gid_t, ngroups_max);

                        r = getgroups(ngroups_max, test_gids);
                        assert_se(r >= 0);
                        n_test_gids = (size_t) r;
                }

                assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) >= 0);

                assert_se(getpeercred(pair[0], &ucred) >= 0);

                assert_se(ucred.uid == test_uid);
                assert_se(ucred.gid == test_gid);
                assert_se(ucred.pid == getpid_cached());

                {
                        _cleanup_free_ gid_t *peer_groups = NULL;

                        r = getpeergroups(pair[0], &peer_groups);
                        assert_se(r >= 0 || IN_SET(r, -EOPNOTSUPP, -ENOPROTOOPT));

                        if (r >= 0) {
                                assert_se((size_t) r == n_test_gids);
                                assert_se(memcmp(peer_groups, test_gids, sizeof(gid_t) * n_test_gids) == 0);
                        }
                }

                safe_close_pair(pair);
                _exit(EXIT_SUCCESS);
        }
}

TEST(passfd_read) {
        static const char file_contents[] = "test contents for passfd";
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) >= 0);

        r = safe_fork("(passfd_read)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                /* Child */
                pair[0] = safe_close(pair[0]);

                char tmpfile[] = "/tmp/test-socket-util-passfd-read-XXXXXX";
                assert_se(write_tmpfile(tmpfile, file_contents) == 0);

                _cleanup_close_ int tmpfd = open(tmpfile, O_RDONLY);
                assert_se(tmpfd >= 0);
                assert_se(unlink(tmpfile) == 0);

                assert_se(send_one_fd(pair[1], tmpfd, MSG_DONTWAIT) == 0);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        _cleanup_close_ int fd = -EBADF;

        pair[1] = safe_close(pair[1]);

        assert_se(receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd) == 0);

        assert_se(fd >= 0);
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        assert_se(n >= 0);
        buf[n] = 0;
        ASSERT_STREQ(buf, file_contents);
}

TEST(passfd_contents_read) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        static const char file_contents[] = "test contents in the file";
        static const char wire_contents[] = "test contents on the wire";
        int r;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) >= 0);

        r = safe_fork("(passfd_contents_read)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                /* Child */
                struct iovec iov = IOVEC_MAKE_STRING(wire_contents);
                char tmpfile[] = "/tmp/test-socket-util-passfd-contents-read-XXXXXX";

                pair[0] = safe_close(pair[0]);

                assert_se(write_tmpfile(tmpfile, file_contents) == 0);

                _cleanup_close_ int tmpfd = open(tmpfile, O_RDONLY);
                assert_se(tmpfd >= 0);
                assert_se(unlink(tmpfile) == 0);

                assert_se(send_one_fd_iov(pair[1], tmpfd, &iov, 1, MSG_DONTWAIT) > 0);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        _cleanup_close_ int fd = -EBADF;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd);
        assert_se(k > 0);
        buf[k] = 0;
        ASSERT_STREQ(buf, wire_contents);

        assert_se(fd >= 0);
        r = read(fd, buf, sizeof(buf)-1);
        assert_se(r >= 0);
        buf[r] = 0;
        ASSERT_STREQ(buf, file_contents);
}

TEST(pass_many_fds_contents_read) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        static const char file_contents[][STRLEN("test contents in the fileX") + 1] = {
                "test contents in the file0",
                "test contents in the file1",
                "test contents in the file2"
        };
        static const char wire_contents[] = "test contents on the wire";
        int r;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) >= 0);

        r = safe_fork("(passfd_contents_read)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                /* Child */
                struct iovec iov = IOVEC_MAKE_STRING(wire_contents);
                char tmpfile[][STRLEN("/tmp/test-socket-util-passfd-contents-read-XXXXXX") + 1] = {
                        "/tmp/test-socket-util-passfd-contents-read-XXXXXX",
                        "/tmp/test-socket-util-passfd-contents-read-XXXXXX",
                        "/tmp/test-socket-util-passfd-contents-read-XXXXXX"
                };
                int tmpfds[3] = EBADF_TRIPLET;

                pair[0] = safe_close(pair[0]);

                for (size_t i = 0; i < 3; ++i) {
                        assert_se(write_tmpfile(tmpfile[i], file_contents[i]) == 0);
                        tmpfds[i] = open(tmpfile[i], O_RDONLY);
                        assert_se(tmpfds[i] >= 0);
                        assert_se(unlink(tmpfile[i]) == 0);
                }

                assert_se(send_many_fds_iov(pair[1], tmpfds, 3, &iov, 1, MSG_DONTWAIT) > 0);
                close_many(tmpfds, 3);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        _cleanup_free_ int *fds = NULL;
        size_t n_fds = 0;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = receive_many_fds_iov(pair[0], &iov, 1, &fds, &n_fds, MSG_DONTWAIT);
        assert_se(k > 0);
        buf[k] = 0;
        ASSERT_STREQ(buf, wire_contents);

        assert_se(n_fds == 3);

        for (size_t i = 0; i < 3; ++i) {
                assert_se(fds[i] >= 0);
                r = read(fds[i], buf, sizeof(buf)-1);
                assert_se(r >= 0);
                buf[r] = 0;
                ASSERT_STREQ(buf, file_contents[i]);
                safe_close(fds[i]);
        }
}

TEST(receive_nopassfd) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        static const char wire_contents[] = "no fd passed here";
        int r;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) >= 0);

        r = safe_fork("(receive_nopassfd)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                /* Child */
                struct iovec iov = IOVEC_MAKE_STRING(wire_contents);

                pair[0] = safe_close(pair[0]);

                assert_se(send_one_fd_iov(pair[1], -1, &iov, 1, MSG_DONTWAIT) > 0);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        int fd = -999;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd);
        assert_se(k > 0);
        buf[k] = 0;
        ASSERT_STREQ(buf, wire_contents);

        /* no fd passed here, confirm it was reset */
        assert_se(fd == -EBADF);
}

TEST(send_nodata_nofd) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) >= 0);

        r = safe_fork("(send_nodata_nofd)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                /* Child */
                pair[0] = safe_close(pair[0]);

                assert_se(send_one_fd_iov(pair[1], -1, NULL, 0, MSG_DONTWAIT) == -EINVAL);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        int fd = -999;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd);
        /* recvmsg() will return errno EAGAIN if nothing was sent */
        assert_se(k == -EAGAIN);

        /* receive_one_fd_iov returned error, so confirm &fd wasn't touched */
        assert_se(fd == -999);
}

TEST(send_emptydata) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) >= 0);

        r = safe_fork("(send_emptydata)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                /* Child */
                pair[0] = safe_close(pair[0]);

                /* This will succeed, since iov is set. */
                assert_se(send_one_fd_iov(pair[1], -1, &iovec_empty, 1, MSG_DONTWAIT) == 0);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        int fd = -999;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd);
        /* receive_one_fd_iov() returns -EIO if an fd is not found and no data was returned. */
        assert_se(k == -EIO);

        /* receive_one_fd_iov returned error, so confirm &fd wasn't touched */
        assert_se(fd == -999);
}

TEST(flush_accept) {
        _cleanup_close_ int listen_stream, listen_dgram, listen_seqpacket, connect_stream, connect_dgram, connect_seqpacket;
        static const union sockaddr_union sa = { .un.sun_family = AF_UNIX };
        union sockaddr_union lsa;
        socklen_t l;

        listen_stream = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(listen_stream >= 0);

        listen_dgram = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(listen_dgram >= 0);

        listen_seqpacket = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(listen_seqpacket >= 0);

        assert_se(flush_accept(listen_stream) < 0);
        assert_se(flush_accept(listen_dgram) < 0);
        assert_se(flush_accept(listen_seqpacket) < 0);

        assert_se(bind(listen_stream, &sa.sa, sizeof(sa_family_t)) >= 0);
        assert_se(bind(listen_dgram, &sa.sa, sizeof(sa_family_t)) >= 0);
        assert_se(bind(listen_seqpacket, &sa.sa, sizeof(sa_family_t)) >= 0);

        assert_se(flush_accept(listen_stream) < 0);
        assert_se(flush_accept(listen_dgram) < 0);
        assert_se(flush_accept(listen_seqpacket) < 0);

        assert_se(listen(listen_stream, SOMAXCONN_DELUXE) >= 0);
        assert_se(listen(listen_dgram, SOMAXCONN_DELUXE) < 0);
        assert_se(listen(listen_seqpacket, SOMAXCONN_DELUXE) >= 0);

        assert_se(flush_accept(listen_stream) >= 0);
        assert_se(flush_accept(listen_dgram) < 0);
        assert_se(flush_accept(listen_seqpacket) >= 0);

        connect_stream = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(connect_stream >= 0);

        connect_dgram = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(connect_dgram >= 0);

        connect_seqpacket = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(connect_seqpacket >= 0);

        l = sizeof(lsa);
        assert_se(getsockname(listen_stream, &lsa.sa, &l) >= 0);
        assert_se(connect(connect_stream, &lsa.sa, l) >= 0);

        l = sizeof(lsa);
        assert_se(getsockname(listen_dgram, &lsa.sa, &l) >= 0);
        assert_se(connect(connect_dgram, &lsa.sa, l) >= 0);

        l = sizeof(lsa);
        assert_se(getsockname(listen_seqpacket, &lsa.sa, &l) >= 0);
        assert_se(connect(connect_seqpacket, &lsa.sa, l) >= 0);

        assert_se(flush_accept(listen_stream) >= 0);
        assert_se(flush_accept(listen_dgram) < 0);
        assert_se(flush_accept(listen_seqpacket) >= 0);
}

TEST(ipv6_enabled) {
        log_info("IPv6 supported: %s", yes_no(socket_ipv6_is_supported()));
        log_info("IPv6 enabled: %s", yes_no(socket_ipv6_is_enabled()));
}

TEST(sockaddr_un_set_path) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(unlink_and_freep) char *sh = NULL;
        _cleanup_free_ char *j = NULL;
        union sockaddr_union sa;
        _cleanup_close_ int fd1, fd2, fd3;

        assert_se(mkdtemp_malloc("/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXXXXXX", &t) >= 0);
        assert_se(strlen(t) > SUN_PATH_LEN);

        assert_se(j = path_join(t, "sock"));
        assert_se(sockaddr_un_set_path(&sa.un, j) == -ENAMETOOLONG); /* too long for AF_UNIX socket */

        assert_se(asprintf(&sh, "/tmp/%" PRIx64, random_u64()) >= 0);
        assert_se(symlink(t, sh) >= 0); /* create temporary symlink, to access it anyway */

        free(j);
        assert_se(j = path_join(sh, "sock"));
        assert_se(sockaddr_un_set_path(&sa.un, j) >= 0);

        fd1 = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(fd1 >= 0);
        assert_se(bind(fd1, &sa.sa, SOCKADDR_LEN(sa)) >= 0);
        assert_se(listen(fd1, 1) >= 0);

        sh = unlink_and_free(sh); /* remove temporary symlink */

        fd2 = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(fd2 >= 0);
        assert_se(connect(fd2, &sa.sa, SOCKADDR_LEN(sa)) < 0);
        assert_se(errno == ENOENT); /* we removed the symlink, must fail */

        free(j);
        assert_se(j = path_join(t, "sock"));

        fd3 = open(j, O_CLOEXEC|O_PATH|O_NOFOLLOW);
        assert_se(fd3 > 0);
        assert_se(sockaddr_un_set_path(&sa.un, FORMAT_PROC_FD_PATH(fd3)) >= 0); /* connect via O_PATH instead, circumventing 108ch limit */

        assert_se(connect(fd2, &sa.sa, SOCKADDR_LEN(sa)) >= 0);
}

TEST(getpeerpidref) {
        _cleanup_close_pair_ int fd[2] = EBADF_PAIR;

        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, fd));

        _cleanup_(pidref_done) PidRef pidref0 = PIDREF_NULL, pidref1 = PIDREF_NULL, pidref_self = PIDREF_NULL, pidref_pid1 = PIDREF_NULL;
        ASSERT_OK(getpeerpidref(fd[0], &pidref0));
        ASSERT_OK(getpeerpidref(fd[1], &pidref1));

        ASSERT_OK(pidref_set_self(&pidref_self));
        ASSERT_OK(pidref_set_pid(&pidref_pid1, 1));

        ASSERT_TRUE(pidref_equal(&pidref0, &pidref1));
        ASSERT_TRUE(pidref_equal(&pidref0, &pidref_self));
        ASSERT_TRUE(pidref_equal(&pidref1, &pidref_self));

        ASSERT_TRUE(!pidref_equal(&pidref_self, &pidref_pid1));
        ASSERT_TRUE(!pidref_equal(&pidref1, &pidref_pid1));
        ASSERT_TRUE(!pidref_equal(&pidref0, &pidref_pid1));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
