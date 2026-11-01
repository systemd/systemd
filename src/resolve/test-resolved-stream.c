/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"

#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-dnstls.h"
#include "resolved-manager.h"
#include "sparse-endian.h"
#include "tests.h"
#include "time-util.h"

static union sockaddr_union server_address;

/* Bytes of the questions & answers used in the test, including TCP DNS 2-byte length prefix */
static const uint8_t QUESTION_A[] =  {
        0x00, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',
        'x' , 'a' , 'm' , 'p' , 'l' , 'e' , 0x03, 'c' , 'o' , 'm' , 0x00, 0x00, 0x01, 0x00, 0x01
};
static const uint8_t QUESTION_AAAA[] =  {
        0x00, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',
        'x' , 'a' , 'm' , 'p' , 'l' , 'e' , 0x03, 'c' , 'o' , 'm' , 0x00, 0x00, 0x1C, 0x00, 0x01
};
static const uint8_t ANSWER_A[] =  {
        0x00, 0x2D, 0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',
        'x' , 'a' , 'm' , 'p' , 'l' , 'e' , 0x03, 'c' , 'o' , 'm' , 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
        0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x52, 0x8D, 0x00, 0x04, 0x5D, 0xB8, 0xD8, 0x22,
};
static const uint8_t ANSWER_AAAA[] =  {
        0x00, 0x39, 0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',
        'x' , 'a' , 'm' , 'p' , 'l' , 'e' , 0x03, 'c' , 'o' , 'm' , 0x00, 0x00, 0x1C, 0x00, 0x01, 0xC0,
        0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x54, 0x4B, 0x00, 0x10, 0x26, 0x06, 0x28, 0x00, 0x02,
        0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xC8, 0x19, 0x46,
};

/**
 * A mock TCP DNS server that asserts certain questions are received
 * and replies with the same answer every time.
 */
static void receive_and_check_question(int fd, const uint8_t *expected_question,
                                       size_t question_size) {
        uint8_t *actual_question;
        size_t n_read = 0;

        actual_question = newa(uint8_t, question_size);
        while (n_read < question_size) {
                ssize_t r = ASSERT_OK_ERRNO(read(fd, actual_question + n_read, question_size - n_read));
                n_read += (size_t)r;
        }
        ASSERT_EQ(n_read, question_size);

        ASSERT_EQ(memcmp(expected_question, actual_question, question_size), 0);
}

static void send_answer(int fd, const uint8_t *answer, size_t answer_size) {
        ASSERT_OK_EQ_ERRNO(write(fd, answer, answer_size), (ssize_t) answer_size);
}

/* Sends two answers together in a single write operation,
 * so they hopefully end up in a single TCP packet / TLS record */
static void send_answers_together(int fd,
                                  const uint8_t *answer1, size_t answer1_size,
                                  const uint8_t *answer2, size_t answer2_size) {
        uint8_t *answer;
        size_t answer_size = answer1_size + answer2_size;

        answer = newa(uint8_t, answer_size);
        memcpy(answer, answer1, answer1_size);
        memcpy(answer + answer1_size, answer2, answer2_size);
        ASSERT_OK_EQ_ERRNO(write(fd, answer, answer_size), (ssize_t) answer_size);
}

static void server_handle(int fd) {
        receive_and_check_question(fd, QUESTION_A, sizeof(QUESTION_A));
        send_answer(fd, ANSWER_A, sizeof(ANSWER_A));

        receive_and_check_question(fd, QUESTION_AAAA, sizeof(QUESTION_AAAA));
        send_answer(fd, ANSWER_AAAA, sizeof(ANSWER_AAAA));

        receive_and_check_question(fd, QUESTION_A, sizeof(QUESTION_A));
        receive_and_check_question(fd, QUESTION_AAAA, sizeof(QUESTION_AAAA));
        send_answers_together(fd, ANSWER_A, sizeof(ANSWER_A),
                                  ANSWER_AAAA, sizeof(ANSWER_AAAA));
}

static void *tcp_dns_server(void *p) {
        _cleanup_close_ int bindfd = -EBADF, acceptfd = -EBADF;

        bindfd = ASSERT_OK_ERRNO(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        ASSERT_OK_ERRNO(setsockopt(bindfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)));
        ASSERT_OK_ERRNO(bind(bindfd, &server_address.sa, sockaddr_len(&server_address)));
        ASSERT_OK_ERRNO(listen(bindfd, 1));
        acceptfd = ASSERT_OK_ERRNO(accept4(bindfd, NULL, NULL, SOCK_CLOEXEC));
        server_handle(acceptfd);
        return NULL;
}

#if ENABLE_DNS_OVER_TLS
/*
 * Spawns a DNS TLS server using the command line "openssl s_server" tool.
 */
static void *tls_dns_server(void *p) {
        int r;
        _cleanup_close_ int fd_server = -EBADF, fd_tls = -EBADF;
        _cleanup_free_ char *cert_path = NULL, *key_path = NULL;
        _cleanup_free_ char *bind_str = NULL;

        ASSERT_OK(get_testdata_dir("test-resolve/selfsigned.cert", &cert_path));
        ASSERT_OK(get_testdata_dir("test-resolve/selfsigned.key", &key_path));

        ASSERT_OK_ERRNO(asprintf(&bind_str, "%s:%d",
                                 IN_ADDR_TO_STRING(server_address.in.sin_family,
                                                   sockaddr_in_addr(&server_address.sa)),
                                 be16toh(server_address.in.sin_port)));

        /* We will hook one of the socketpair ends to OpenSSL's TLS server
         * stdin/stdout, so we will be able to read and write plaintext
         * from the other end's file descriptor like an usual TCP server */
        {
                int fd[2];
                ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, fd));
                fd_server = fd[0];
                fd_tls = fd[1];
        }

        _cleanup_(pidref_done) PidRef openssl_pidref = PIDREF_NULL;
        r = ASSERT_OK(pidref_safe_fork_full(
                        "(test-resolved-stream-tls-openssl)",
                        (int[]) { fd_tls, fd_tls, STDOUT_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_REOPEN_LOG,
                        &openssl_pidref));
        if (r == 0) {
                /* Child */
                execlp("openssl", "openssl", "s_server", "-accept", bind_str,
                       "-key", key_path, "-cert", cert_path,
                       "-quiet", "-naccept", "1", NULL);
                log_error("exec failed, is something wrong with the 'openssl' command?");
                _exit(EXIT_FAILURE);
        } else {
                pthread_mutex_t *server_lock = (pthread_mutex_t *)p;

                server_handle(fd_server);

                /* Once the test is done kill the TLS server to release the port */
                ASSERT_EQ(pthread_mutex_lock(server_lock), 0);
                ASSERT_OK(pidref_kill(&openssl_pidref, SIGTERM));
                ASSERT_OK(pidref_wait_for_terminate(&openssl_pidref, /* ret_si= */ NULL));
                ASSERT_EQ(pthread_mutex_unlock(server_lock), 0);
        }

        return NULL;
}
#endif

static const char *TEST_DOMAIN = "example.com";
static const uint64_t EVENT_TIMEOUT_USEC = 5 * 1000 * 1000;

static void send_simple_question(DnsStream *stream, uint16_t type) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, type, TEST_DOMAIN));
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        ASSERT_OK(dns_packet_append_question(p, question));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(dns_question_size(question));
        ASSERT_OK(dns_stream_write_packet(stream, p));
}

static const size_t MAX_RECEIVED_PACKETS = 2;
static DnsPacket *received_packets[2] = {};
static size_t n_received_packets = 0;

static int on_stream_packet(DnsStream *stream, DnsPacket *p) {
        ASSERT_LT(n_received_packets, MAX_RECEIVED_PACKETS);
        ASSERT_NOT_NULL(received_packets[n_received_packets++] = dns_packet_ref(p));
        return 0;
}

static int on_stream_complete_do_nothing(DnsStream *s, int error) {
        return 0;
}

static void test_dns_stream(bool tls) {
        Manager manager = {};
         _cleanup_(dns_stream_unrefp) DnsStream *stream = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_close_ int clientfd = -EBADF;
        int r;

        void *(*server_entrypoint)(void *);
        pthread_t server_thread;
        pthread_mutex_t server_lock;

        log_info("test-resolved-stream: Started %s test", tls ? "TLS" : "TCP");

#if ENABLE_DNS_OVER_TLS
        if (tls)
                /* For TLS mode, use DNS_OVER_TLS_OPPORTUNISTIC instead of DNS_OVER_TLS_YES, just to make
                 * certificate validation more lenient, allowing us to use self-signed certificates.  We
                 * never downgrade, everything we test always goes over TLS */
                manager.dns_over_tls_mode = DNS_OVER_TLS_OPPORTUNISTIC;
#endif

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

        /* Set up a mock DNS (over TCP or TLS) server */
        server_entrypoint = tcp_dns_server;
#if ENABLE_DNS_OVER_TLS
        if (tls)
                server_entrypoint = tls_dns_server;
#endif
        ASSERT_EQ(pthread_mutex_init(&server_lock, NULL), 0);
        ASSERT_EQ(pthread_mutex_lock(&server_lock), 0);
        ASSERT_EQ(pthread_create(&server_thread, NULL, server_entrypoint, &server_lock), 0);

        /* Create a socket client and connect to the TCP or TLS server
         * The server may not be up immediately, so try to connect a few times before failing */
        clientfd = ASSERT_OK_ERRNO(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));

        for (int i = 0; i < 100; i++) {
                r = connect(clientfd, &server_address.sa, sockaddr_len(&server_address));
                if (r >= 0)
                        break;
                usleep_safe(EVENT_TIMEOUT_USEC / 100);
        }
        ASSERT_OK_ERRNO(r);

        /* systemd-resolved uses (and requires) the socket to be in nonblocking mode */
        ASSERT_OK_ERRNO(fcntl(clientfd, F_SETFL, O_NONBLOCK));

        /* Initialize DNS stream (disabling the default self-destruction
           behaviour when no complete callback is set) */
        ASSERT_OK(dns_stream_new(&manager, &stream, DNS_STREAM_LOOKUP, DNS_PROTOCOL_DNS,
                                 TAKE_FD(clientfd), /* tfo_address= */ NULL, on_stream_packet, on_stream_complete_do_nothing,
                                 DNS_STREAM_DEFAULT_TIMEOUT_USEC));
#if ENABLE_DNS_OVER_TLS
        if (tls) {
                DnsServer server = {
                        .manager = &manager,
                        .family = server_address.sa.sa_family,
                        .address = *sockaddr_in_addr(&server_address.sa),
                };

                ASSERT_OK(dnstls_manager_init(&manager));
                ASSERT_OK(dnstls_stream_connect_tls(stream, &server));
        }
#endif

        /* Test: Question of type A and associated answer */
        log_info("test-resolved-stream: A record");
        send_simple_question(stream, DNS_TYPE_A);
        while (n_received_packets != 1)
                ASSERT_OK_POSITIVE(sd_event_run(event, EVENT_TIMEOUT_USEC));
        ASSERT_NOT_NULL(DNS_PACKET_DATA(received_packets[0]));
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(received_packets[0]),
                         ANSWER_A + 2, sizeof(ANSWER_A) - 2), 0);
        dns_packet_unref(TAKE_PTR(received_packets[0]));
        n_received_packets = 0;

        /* Test: Question of type AAAA and associated answer */
        log_info("test-resolved-stream: AAAA record");
        send_simple_question(stream, DNS_TYPE_AAAA);
        while (n_received_packets != 1)
                ASSERT_OK_POSITIVE(sd_event_run(event, EVENT_TIMEOUT_USEC));
        ASSERT_NOT_NULL(DNS_PACKET_DATA(received_packets[0]));
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(received_packets[0]),
                         ANSWER_AAAA + 2, sizeof(ANSWER_AAAA) - 2), 0);
        dns_packet_unref(TAKE_PTR(received_packets[0]));
        n_received_packets = 0;

        /* Test: Question of type A and AAAA and associated answers
         * Both answers are sent back in a single packet or TLS record
         * (tests the fix of PR #22132: "Fix DoT timeout on multiple answer records") */
        log_info("test-resolved-stream: A + AAAA record");
        send_simple_question(stream, DNS_TYPE_A);
        send_simple_question(stream, DNS_TYPE_AAAA);

        while (n_received_packets != 2)
                ASSERT_OK_POSITIVE(sd_event_run(event, EVENT_TIMEOUT_USEC));
        ASSERT_NOT_NULL(DNS_PACKET_DATA(received_packets[0]));
        ASSERT_NOT_NULL(DNS_PACKET_DATA(received_packets[1]));
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(received_packets[0]),
                         ANSWER_A + 2, sizeof(ANSWER_A) - 2), 0);
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(received_packets[1]),
                         ANSWER_AAAA + 2, sizeof(ANSWER_AAAA) - 2), 0);
        dns_packet_unref(TAKE_PTR(received_packets[0]));
        dns_packet_unref(TAKE_PTR(received_packets[1]));
        n_received_packets = 0;

#if ENABLE_DNS_OVER_TLS
        if (tls)
                dnstls_manager_free(&manager);
#endif

        /* Stop the DNS server */
        ASSERT_EQ(pthread_mutex_unlock(&server_lock), 0);
        ASSERT_EQ(pthread_join(server_thread, NULL), 0);
        ASSERT_EQ(pthread_mutex_destroy(&server_lock), 0);

        log_info("test-resolved-stream: Finished %s test", tls ? "TLS" : "TCP");
}

static int try_isolate_network(void) {
        _cleanup_close_ int socket_fd = -EBADF;
        int r;

        /* First test if CLONE_NEWUSER/CLONE_NEWNET can actually work for us, i.e. we can open the namespaces
         * and then still access the build dir we are run from. We do that in a child process since it's
         * nasty if we have to go back from the namespace once we entered it and realized it cannot work. */
        r = pidref_safe_fork("(usernstest)", FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT, /* ret= */ NULL);
        if (r == 0) { /* child */
                _cleanup_free_ char *rt = NULL, *d = NULL;

                if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                        log_warning_errno(errno, "test-resolved-stream: Can't create user and network ns, running on host: %m");
                        _exit(EXIT_FAILURE);
                }

                ASSERT_OK(get_process_exe(/* pid= */ 0, &rt));
                ASSERT_OK(path_extract_directory(rt, &d));

                if (access(d, F_OK) < 0) {
                        log_warning_errno(errno, "test-resolved-stream: Can't access /proc/self/exe from user/network ns, running on host: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }
        if (r == -EPROTO) /* EPROTO means nonzero exit code of child, i.e. the tests in the child failed */
                return 0;
        ASSERT_OK_POSITIVE(r);

        /* Now that we know that the unshare() is safe, let's actually do it */
        ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER | CLONE_NEWNET));

        /* Bring up the loopback interface on the newly created network namespace */
        struct ifreq req = { .ifr_ifindex = 1 };
        socket_fd = ASSERT_OK_ERRNO(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        ASSERT_OK_ERRNO(ioctl(socket_fd, SIOCGIFNAME, &req));
        ASSERT_OK_ERRNO(ioctl(socket_fd, SIOCGIFFLAGS, &req));
        ASSERT_TRUE(FLAGS_SET(req.ifr_flags, IFF_LOOPBACK));
        req.ifr_flags |= IFF_UP;
        /* Do not assert on this, fails in the Ubuntu 24.04 CI environment */
        r = RET_NERRNO(ioctl(socket_fd, SIOCSIFFLAGS, &req));
        if (r < 0)
                return r;

        return 0;
}

int main(int argc, char **argv) {
        server_address = (union sockaddr_union) {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(random_u64_range(UINT16_MAX - 1024) + 1024),
                .in.sin_addr.s_addr = htobe32(INADDR_LOOPBACK)
        };
        int r;

        test_setup_logging(LOG_DEBUG);

        r = try_isolate_network();
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return log_tests_skipped("lacking privileges");
        ASSERT_OK(r);

        test_dns_stream(/* tls= */ false);
#if ENABLE_DNS_OVER_TLS
        if (system("openssl version >/dev/null 2>&1") != 0)
                return log_tests_skipped("Skipping TLS test since the 'openssl' command does not seem to be available");
        test_dns_stream(/* tls= */ true);
#endif

        return 0;
}
