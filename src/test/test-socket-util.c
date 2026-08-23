/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <grp.h>
#include <linux/pkt_sched.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fs-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

assert_cc(SUN_PATH_LEN == 108);

TEST(ifname_valid) {
        ASSERT_TRUE(ifname_valid("foo"));
        ASSERT_TRUE(ifname_valid("eth0"));

        ASSERT_FALSE(ifname_valid("0"));
        ASSERT_FALSE(ifname_valid("99"));
        ASSERT_TRUE(ifname_valid("a99"));
        ASSERT_TRUE(ifname_valid("99a"));

        ASSERT_FALSE(ifname_valid(NULL));
        ASSERT_FALSE(ifname_valid(""));
        ASSERT_FALSE(ifname_valid(" "));
        ASSERT_FALSE(ifname_valid(" foo"));
        ASSERT_FALSE(ifname_valid("bar\n"));
        ASSERT_FALSE(ifname_valid("."));
        ASSERT_FALSE(ifname_valid(".."));
        ASSERT_TRUE(ifname_valid("foo.bar"));
        ASSERT_FALSE(ifname_valid("x:y"));

        ASSERT_TRUE(ifname_valid_full("xxxxxxxxxxxxxxx", 0));
        ASSERT_FALSE(ifname_valid_full("xxxxxxxxxxxxxxxx", 0));
        ASSERT_TRUE(ifname_valid_full("xxxxxxxxxxxxxxxx", IFNAME_VALID_ALTERNATIVE));
        ASSERT_TRUE(ifname_valid_full("xxxxxxxxxxxxxxxx", IFNAME_VALID_ALTERNATIVE));
        ASSERT_FALSE(ifname_valid_full("999", IFNAME_VALID_ALTERNATIVE));
        ASSERT_TRUE(ifname_valid_full("999", IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC));
        ASSERT_FALSE(ifname_valid_full("0", IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC));
}

static void test_socket_print_unix_one(const char *in, size_t len_in, const char *expected) {
        _cleanup_free_ char *out = NULL, *c = NULL;

        ASSERT_LE(len_in, SUN_PATH_LEN);
        SocketAddress a = { .sockaddr = { .un = { .sun_family = AF_UNIX } },
                            .size = offsetof(struct sockaddr_un, sun_path) + len_in,
                            .type = SOCK_STREAM,
        };
        memcpy(a.sockaddr.un.sun_path, in, len_in);

        ASSERT_OK(socket_address_print(&a, &out));
        ASSERT_NOT_NULL(c = cescape(in));
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

        ASSERT_TRUE(sockaddr_equal(&a, &a));
        ASSERT_TRUE(sockaddr_equal(&a, &b));
        ASSERT_TRUE(sockaddr_equal(&d, &d));
        ASSERT_TRUE(sockaddr_equal(&e, &e));
        ASSERT_FALSE(sockaddr_equal(&a, &c));
        ASSERT_FALSE(sockaddr_equal(&b, &c));
        ASSERT_FALSE(sockaddr_equal(&a, &e));
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

        ASSERT_EQ(sockaddr_un_len(&fs), offsetof(struct sockaddr_un, sun_path) + strlen(fs.sun_path) + 1);
        ASSERT_EQ(sockaddr_un_len(&abstract), offsetof(struct sockaddr_un, sun_path) + 1 + strlen(abstract.sun_path + 1));
}

TEST(in_addr_is_multicast) {
        union in_addr_union a, b;
        int f;

        ASSERT_OK(in_addr_from_string_auto("192.168.3.11", &f, &a));
        ASSERT_OK_EQ(in_addr_is_multicast(f, &a), 0);

        ASSERT_OK(in_addr_from_string_auto("224.0.0.1", &f, &a));
        ASSERT_OK_EQ(in_addr_is_multicast(f, &a), 1);

        ASSERT_OK(in_addr_from_string_auto("FF01:0:0:0:0:0:0:1", &f, &b));
        ASSERT_OK_EQ(in_addr_is_multicast(f, &b), 1);

        ASSERT_OK(in_addr_from_string_auto("2001:db8::c:69b:aeff:fe53:743e", &f, &b));
        ASSERT_OK_EQ(in_addr_is_multicast(f, &b), 0);
}

TEST(getpeercred_getpeergroups) {
        int r;

        r = ASSERT_OK(pidref_safe_fork("(getpeercred)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL));

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

                        ASSERT_OK(fully_set_uid_gid(test_uid, test_gid, test_gids, n_test_gids));
                } else {
                        test_uid = getuid();
                        test_gid = getgid();

                        int ngroups_max = ASSERT_OK_POSITIVE(sysconf_ngroups_max());

                        test_gids = newa(gid_t, ngroups_max);

                        r = ASSERT_OK_ERRNO(getgroups(ngroups_max, test_gids));
                        n_test_gids = (size_t) r;
                }

                ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));

                ASSERT_OK(getpeercred(pair[0], &ucred));

                ASSERT_EQ(ucred.uid, test_uid);
                ASSERT_EQ(ucred.gid, test_gid);
                ASSERT_EQ(ucred.pid, getpid_cached());

                {
                        _cleanup_free_ gid_t *peer_groups = NULL;

                        r = ASSERT_OK_OR(getpeergroups(pair[0], &peer_groups), -EOPNOTSUPP, -ENOPROTOOPT);

                        if (r >= 0) {
                                ASSERT_EQ((size_t) r, n_test_gids);
                                ASSERT_EQ(memcmp(peer_groups, test_gids, sizeof(gid_t) * n_test_gids), 0);
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

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));

        r = ASSERT_OK(pidref_safe_fork("(passfd_read)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL));

        if (r == 0) {
                /* Child */
                pair[0] = safe_close(pair[0]);

                char tmpfile[] = "/tmp/test-socket-util-passfd-read-XXXXXX";
                ASSERT_OK_ZERO(write_tmpfile(tmpfile, file_contents));

                _cleanup_close_ int tmpfd = ASSERT_OK_ERRNO(open(tmpfile, O_RDONLY));
                ASSERT_OK_ERRNO(unlink(tmpfile));

                ASSERT_OK_ZERO(send_one_fd(pair[1], tmpfd, MSG_DONTWAIT));
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        _cleanup_close_ int fd = -EBADF;

        pair[1] = safe_close(pair[1]);

        ASSERT_OK_ZERO(receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd));

        ASSERT_OK(fd);
        ssize_t n = ASSERT_OK_ERRNO(read(fd, buf, sizeof(buf)-1));
        buf[n] = 0;
        ASSERT_STREQ(buf, file_contents);
}

TEST(passfd_contents_read) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        static const char file_contents[] = "test contents in the file";
        static const char wire_contents[] = "test contents on the wire";
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));

        r = ASSERT_OK(pidref_safe_fork("(passfd_contents_read)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL));

        if (r == 0) {
                /* Child */
                struct iovec iov = IOVEC_MAKE_STRING(wire_contents);
                char tmpfile[] = "/tmp/test-socket-util-passfd-contents-read-XXXXXX";

                pair[0] = safe_close(pair[0]);

                ASSERT_OK_ZERO(write_tmpfile(tmpfile, file_contents));

                _cleanup_close_ int tmpfd = ASSERT_OK_ERRNO(open(tmpfile, O_RDONLY));
                ASSERT_OK_ERRNO(unlink(tmpfile));

                ASSERT_OK_POSITIVE(send_one_fd_iov(pair[1], tmpfd, &iov, 1, MSG_DONTWAIT));
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        _cleanup_close_ int fd = -EBADF;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = ASSERT_OK_POSITIVE(receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd));
        buf[k] = 0;
        ASSERT_STREQ(buf, wire_contents);

        ASSERT_OK(fd);
        r = ASSERT_OK_ERRNO(read(fd, buf, sizeof(buf)-1));
        buf[r] = 0;
        ASSERT_STREQ(buf, file_contents);
}

TEST(receive_nopassfd) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        static const char wire_contents[] = "no fd passed here";
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));

        r = ASSERT_OK(pidref_safe_fork("(receive_nopassfd)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL));

        if (r == 0) {
                /* Child */
                struct iovec iov = IOVEC_MAKE_STRING(wire_contents);

                pair[0] = safe_close(pair[0]);

                ASSERT_OK_POSITIVE(send_one_fd_iov(pair[1], -1, &iov, 1, MSG_DONTWAIT));
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        int fd = -999;
        ssize_t k;

        pair[1] = safe_close(pair[1]);

        k = ASSERT_OK_POSITIVE(receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd));
        buf[k] = 0;
        ASSERT_STREQ(buf, wire_contents);

        /* no fd passed here, confirm it was reset */
        ASSERT_EQ(fd, -EBADF);
}

TEST(send_nodata_nofd) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));

        r = ASSERT_OK(pidref_safe_fork("(send_nodata_nofd)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL));

        if (r == 0) {
                /* Child */
                pair[0] = safe_close(pair[0]);

                ASSERT_ERROR(send_one_fd_iov(pair[1], -1, NULL, 0, MSG_DONTWAIT), EINVAL);
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        int fd = -999;

        pair[1] = safe_close(pair[1]);

        /* recvmsg() will return errno EAGAIN if nothing was sent */
        ASSERT_ERROR(receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd), EAGAIN);

        /* receive_one_fd_iov returned error, so confirm &fd wasn't touched */
        ASSERT_EQ(fd, -999);
}

TEST(send_emptydata) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));

        r = ASSERT_OK(pidref_safe_fork("(send_emptydata)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL));

        if (r == 0) {
                /* Child */
                pair[0] = safe_close(pair[0]);

                /* This will succeed, since iov is set. */
                ASSERT_OK_ZERO(send_one_fd_iov(pair[1], -1, &iovec_empty, 1, MSG_DONTWAIT));
                _exit(EXIT_SUCCESS);
        }

        /* Parent */
        char buf[64];
        struct iovec iov = IOVEC_MAKE(buf, sizeof(buf)-1);
        int fd = -999;

        pair[1] = safe_close(pair[1]);

        /* receive_one_fd_iov() returns -EIO if an fd is not found and no data was returned. */
        ASSERT_ERROR(receive_one_fd_iov(pair[0], &iov, 1, MSG_DONTWAIT, &fd), EIO);

        /* receive_one_fd_iov returned error, so confirm &fd wasn't touched */
        ASSERT_EQ(fd, -999);
}

TEST(flush_accept) {
        _cleanup_close_ int listen_stream, listen_dgram, listen_seqpacket, connect_stream, connect_dgram, connect_seqpacket;
        static const union sockaddr_union sa = { .un.sun_family = AF_UNIX };
        union sockaddr_union lsa;
        socklen_t l;

        ASSERT_OK_ERRNO(listen_stream = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        ASSERT_OK_ERRNO(listen_dgram = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        ASSERT_OK_ERRNO(listen_seqpacket = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));

        ASSERT_FAIL(flush_accept(listen_stream));
        ASSERT_FAIL(flush_accept(listen_dgram));
        ASSERT_FAIL(flush_accept(listen_seqpacket));

        ASSERT_OK_ERRNO(bind(listen_stream, &sa.sa, sizeof(sa_family_t)));
        ASSERT_OK_ERRNO(bind(listen_dgram, &sa.sa, sizeof(sa_family_t)));
        ASSERT_OK_ERRNO(bind(listen_seqpacket, &sa.sa, sizeof(sa_family_t)));

        ASSERT_FAIL(flush_accept(listen_stream));
        ASSERT_FAIL(flush_accept(listen_dgram));
        ASSERT_FAIL(flush_accept(listen_seqpacket));

        ASSERT_OK_ERRNO(listen(listen_stream, SOMAXCONN_DELUXE));
        ASSERT_FAIL(listen(listen_dgram, SOMAXCONN_DELUXE));
        ASSERT_OK_ERRNO(listen(listen_seqpacket, SOMAXCONN_DELUXE));

        ASSERT_OK(flush_accept(listen_stream));
        ASSERT_FAIL(flush_accept(listen_dgram));
        ASSERT_OK(flush_accept(listen_seqpacket));

        ASSERT_OK_ERRNO(connect_stream = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        ASSERT_OK_ERRNO(connect_dgram = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));
        ASSERT_OK_ERRNO(connect_seqpacket = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0));

        l = sizeof(lsa);
        ASSERT_OK_ERRNO(getsockname(listen_stream, &lsa.sa, &l));
        ASSERT_OK_ERRNO(connect(connect_stream, &lsa.sa, l));

        l = sizeof(lsa);
        ASSERT_OK_ERRNO(getsockname(listen_dgram, &lsa.sa, &l));
        ASSERT_OK_ERRNO(connect(connect_dgram, &lsa.sa, l));

        l = sizeof(lsa);
        ASSERT_OK_ERRNO(getsockname(listen_seqpacket, &lsa.sa, &l));
        ASSERT_OK_ERRNO(connect(connect_seqpacket, &lsa.sa, l));

        ASSERT_OK(flush_accept(listen_stream));
        ASSERT_FAIL(flush_accept(listen_dgram));
        ASSERT_OK(flush_accept(listen_seqpacket));
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

        ASSERT_OK(mkdtemp_malloc("/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXXXXXX", &t));
        ASSERT_GT(strlen(t), SUN_PATH_LEN);

        ASSERT_NOT_NULL(j = path_join(t, "sock"));
        ASSERT_ERROR(sockaddr_un_set_path(&sa.un, j), ENAMETOOLONG); /* too long for AF_UNIX socket */

        ASSERT_OK_ERRNO(asprintf(&sh, "/tmp/%" PRIx64, random_u64()));
        ASSERT_OK_ERRNO(symlink(t, sh)); /* create temporary symlink, to access it anyway */

        free(j);
        ASSERT_NOT_NULL(j = path_join(sh, "sock"));
        ASSERT_OK(sockaddr_un_set_path(&sa.un, j));

        ASSERT_OK_ERRNO(fd1 = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0));
        ASSERT_OK_ERRNO(bind(fd1, &sa.sa, sockaddr_len(&sa)));
        ASSERT_OK_ERRNO(listen(fd1, 1));

        sh = unlink_and_free(sh); /* remove temporary symlink */

        ASSERT_OK_ERRNO(fd2 = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0));
        ASSERT_ERROR_ERRNO(connect(fd2, &sa.sa, sockaddr_len(&sa)), ENOENT); /* we removed the symlink, must fail */

        free(j);
        ASSERT_NOT_NULL(j = path_join(t, "sock"));

        ASSERT_OK_ERRNO(fd3 = open(j, O_CLOEXEC|O_PATH|O_NOFOLLOW));
        ASSERT_OK(sockaddr_un_set_path(&sa.un, FORMAT_PROC_FD_PATH(fd3))); /* connect via O_PATH instead, circumventing 108ch limit */

        ASSERT_OK_ERRNO(connect(fd2, &sa.sa, sockaddr_len(&sa)));
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

TEST(tos_to_priority) {
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS7), TC_PRIO_CONTROL);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS6), TC_PRIO_CONTROL);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS5), TC_PRIO_INTERACTIVE);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS4), TC_PRIO_INTERACTIVE);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS3), TC_PRIO_INTERACTIVE_BULK);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS2), TC_PRIO_INTERACTIVE_BULK);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS1), TC_PRIO_BULK);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS0), TC_PRIO_BESTEFFORT);

        /* check if lower bits are correctly filtered. */
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS7 | IPTOS_LOWDELAY), TC_PRIO_CONTROL);
        ASSERT_EQ(tos_to_priority(IPTOS_CLASS_CS1 | IPTOS_LOWCOST), TC_PRIO_BULK);

        ASSERT_EQ(tos_to_priority(0x00), TC_PRIO_BESTEFFORT);
        ASSERT_EQ(tos_to_priority(0xff), TC_PRIO_CONTROL);
}

TEST(socket_xattr_supported) {
        int r;

        r = socket_xattr_supported();
        ASSERT_OK(r);

        log_info("Extended attributes on socket inodes supported: %s", yes_no(r));

        /* A second call must agree with the first. */
        ASSERT_EQ(socket_xattr_supported(), r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
