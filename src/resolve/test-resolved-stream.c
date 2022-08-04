/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"
#if ENABLE_DNS_OVER_TLS
#include "resolved-dnstls.h"
#endif
#include "resolved-dns-server.h"
#include "resolved-dns-stream.h"
#include "resolved-manager.h"
#include "sd-event.h"
#include "sparse-endian.h"
#include "tests.h"

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
                ssize_t r = read(fd, actual_question + n_read, question_size - n_read);
                assert_se(r >= 0);
                n_read += (size_t)r;
        }
        assert_se(n_read == question_size);

        assert_se(memcmp(expected_question, actual_question, question_size) == 0);
}

static void send_answer(int fd, const uint8_t *answer, size_t answer_size) {
        assert_se(write(fd, answer, answer_size) == (ssize_t)answer_size);
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
        assert_se(write(fd, answer, answer_size) == (ssize_t)answer_size);
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
        _cleanup_close_ int bindfd = -1, acceptfd = -1;

        assert_se((bindfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) >= 0);
        assert_se(setsockopt(bindfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) >= 0);
        assert_se(bind(bindfd, &server_address.sa, SOCKADDR_LEN(server_address)) >= 0);
        assert_se(listen(bindfd, 1) >= 0);
        assert_se((acceptfd = accept(bindfd, NULL, NULL)) >= 0);
        server_handle(acceptfd);
        return NULL;
}

#if ENABLE_DNS_OVER_TLS
/*
 * Spawns a DNS TLS server using the command line "openssl s_server" tool.
 */
static void *tls_dns_server(void *p) {
        pid_t openssl_pid;
        int r;
        _cleanup_close_ int fd_server = -1, fd_tls = -1;
        _cleanup_free_ char *cert_path = NULL, *key_path = NULL;
        _cleanup_free_ char *bind_str = NULL;

        assert_se(get_testdata_dir("test-resolve/selfsigned.cert", &cert_path) >= 0);
        assert_se(get_testdata_dir("test-resolve/selfsigned.key", &key_path) >= 0);

        assert_se(asprintf(&bind_str, "%s:%d",
                           IN_ADDR_TO_STRING(server_address.in.sin_family,
                                             sockaddr_in_addr(&server_address.sa)),
                           be16toh(server_address.in.sin_port)) >= 0);

        /* We will hook one of the socketpair ends to OpenSSL's TLS server
         * stdin/stdout, so we will be able to read and write plaintext
         * from the other end's file descriptor like an usual TCP server */
        {
                int fd[2];
                assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) >= 0);
                fd_server = fd[0];
                fd_tls = fd[1];
        }

        r = safe_fork_full("(test-resolved-stream-tls-openssl)", (int[]) { fd_server, fd_tls }, 2,
                FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_REOPEN_LOG, &openssl_pid);
        assert_se(r >= 0);
        if (r == 0) {
                /* Child */
                assert_se(dup2(fd_tls, STDIN_FILENO) >= 0);
                assert_se(dup2(fd_tls, STDOUT_FILENO) >= 0);
                close(TAKE_FD(fd_server));
                close(TAKE_FD(fd_tls));

                execlp("openssl", "openssl", "s_server", "-accept", bind_str,
                       "-key", key_path, "-cert", cert_path,
                       "-quiet", "-naccept", "1", NULL);
                log_error("exec failed, is something wrong with the 'openssl' command?");
                _exit(EXIT_FAILURE);
        } else {
                pthread_mutex_t *server_lock = (pthread_mutex_t *)p;

                server_handle(fd_server);

                /* Once the test is done kill the TLS server to release the port */
                assert_se(pthread_mutex_lock(server_lock) == 0);
                assert_se(kill(openssl_pid, SIGTERM) >= 0);
                assert_se(waitpid(openssl_pid, NULL, 0) >= 0);
                assert_se(pthread_mutex_unlock(server_lock) == 0);
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

        assert_se(dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX) >= 0);
        assert_se(question = dns_question_new(1));
        assert_se(key = dns_resource_key_new(DNS_CLASS_IN, type, TEST_DOMAIN));
        assert_se(dns_question_add(question, key, 0) >= 0);
        assert_se(dns_packet_append_question(p, question) >= 0);
        DNS_PACKET_HEADER(p)->qdcount = htobe16(dns_question_size(question));
        assert_se(dns_stream_write_packet(stream, p) >= 0);
}

static const size_t MAX_RECEIVED_PACKETS = 2;
static DnsPacket *received_packets[2] = {};
static size_t n_received_packets = 0;

static int on_stream_packet(DnsStream *stream, DnsPacket *p) {
        assert_se(n_received_packets < MAX_RECEIVED_PACKETS);
        assert_se(received_packets[n_received_packets++] = dns_packet_ref(p));
        return 0;
}

static int on_stream_complete_do_nothing(DnsStream *s, int error) {
        return 0;
}

static void test_dns_stream(bool tls) {
        Manager manager = {};
         _cleanup_(dns_stream_unrefp) DnsStream *stream = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_close_ int clientfd = -1;
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

        assert_se(sd_event_new(&event) >= 0);
        manager.event = event;

        /* Set up a mock DNS (over TCP or TLS) server */
        server_entrypoint = tcp_dns_server;
#if ENABLE_DNS_OVER_TLS
        if (tls)
                server_entrypoint = tls_dns_server;
#endif
        assert_se(pthread_mutex_init(&server_lock, NULL) == 0);
        assert_se(pthread_mutex_lock(&server_lock) == 0);
        assert_se(pthread_create(&server_thread, NULL, server_entrypoint, &server_lock) == 0);

        /* Create a socket client and connect to the TCP or TLS server
         * The server may not be up immediately, so try to connect a few times before failing */
        assert_se((clientfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) >= 0);

        for (int i = 0; i < 100; i++) {
                r = connect(clientfd, &server_address.sa, SOCKADDR_LEN(server_address));
                if (r >= 0)
                        break;
                usleep(EVENT_TIMEOUT_USEC / 100);
        }
        assert_se(r >= 0);

        /* systemd-resolved uses (and requires) the socket to be in nonblocking mode */
        assert_se(fcntl(clientfd, F_SETFL, O_NONBLOCK) >= 0);

        /* Initialize DNS stream (disabling the default self-destruction
           behaviour when no complete callback is set) */
        assert_se(dns_stream_new(&manager, &stream, DNS_STREAM_LOOKUP, DNS_PROTOCOL_DNS,
                                 TAKE_FD(clientfd), NULL, on_stream_packet, on_stream_complete_do_nothing,
                                 DNS_STREAM_DEFAULT_TIMEOUT_USEC) >= 0);
#if ENABLE_DNS_OVER_TLS
        if (tls) {
                DnsServer server = {
                        .manager = &manager,
                        .family = server_address.sa.sa_family,
                        .address = *sockaddr_in_addr(&server_address.sa),
                };

                assert_se(dnstls_manager_init(&manager) >= 0);
                assert_se(dnstls_stream_connect_tls(stream, &server) >= 0);
        }
#endif

        /* Test: Question of type A and associated answer */
        log_info("test-resolved-stream: A record");
        send_simple_question(stream, DNS_TYPE_A);
        while (n_received_packets != 1)
                assert_se(sd_event_run(event, EVENT_TIMEOUT_USEC) >= 1);
        assert_se(DNS_PACKET_DATA(received_packets[0]));
        assert_se(memcmp(DNS_PACKET_DATA(received_packets[0]),
                         ANSWER_A + 2, sizeof(ANSWER_A) - 2) == 0);
        dns_packet_unref(TAKE_PTR(received_packets[0]));
        n_received_packets = 0;

        /* Test: Question of type AAAA and associated answer */
        log_info("test-resolved-stream: AAAA record");
        send_simple_question(stream, DNS_TYPE_AAAA);
        while (n_received_packets != 1)
                assert_se(sd_event_run(event, EVENT_TIMEOUT_USEC) >= 1);
        assert_se(DNS_PACKET_DATA(received_packets[0]));
        assert_se(memcmp(DNS_PACKET_DATA(received_packets[0]),
                         ANSWER_AAAA + 2, sizeof(ANSWER_AAAA) - 2) == 0);
        dns_packet_unref(TAKE_PTR(received_packets[0]));
        n_received_packets = 0;

        /* Test: Question of type A and AAAA and associated answers
         * Both answers are sent back in a single packet or TLS record
         * (tests the fix of PR #22132: "Fix DoT timeout on multiple answer records") */
        log_info("test-resolved-stream: A + AAAA record");
        send_simple_question(stream, DNS_TYPE_A);
        send_simple_question(stream, DNS_TYPE_AAAA);

        while (n_received_packets != 2)
                assert_se(sd_event_run(event, EVENT_TIMEOUT_USEC) >= 1);
        assert_se(DNS_PACKET_DATA(received_packets[0]));
        assert_se(DNS_PACKET_DATA(received_packets[1]));
        assert_se(memcmp(DNS_PACKET_DATA(received_packets[0]),
                         ANSWER_A + 2, sizeof(ANSWER_A) - 2) == 0);
        assert_se(memcmp(DNS_PACKET_DATA(received_packets[1]),
                         ANSWER_AAAA + 2, sizeof(ANSWER_AAAA) - 2) == 0);
        dns_packet_unref(TAKE_PTR(received_packets[0]));
        dns_packet_unref(TAKE_PTR(received_packets[1]));
        n_received_packets = 0;

#if ENABLE_DNS_OVER_TLS
        if (tls)
                dnstls_manager_free(&manager);
#endif

        /* Stop the DNS server */
        assert_se(pthread_mutex_unlock(&server_lock) == 0);
        assert_se(pthread_join(server_thread, NULL) == 0);
        assert_se(pthread_mutex_destroy(&server_lock) == 0);

        log_info("test-resolved-stream: Finished %s test", tls ? "TLS" : "TCP");
}

static void try_isolate_network(void) {
        _cleanup_close_ int socket_fd = -1;
        int r;

        /* First test if CLONE_NEWUSER/CLONE_NEWNET can actually work for us, i.e. we can open the namespaces
         * and then still access the build dir we are run from. We do that in a child process since it's
         * nasty if we have to go back from the namespace once we entered it and realized it cannot work. */
        r = safe_fork("(usernstest)", FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) { /* child */
                _cleanup_free_ char *rt = NULL, *d = NULL;

                if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                        log_warning_errno(errno, "test-resolved-stream: Can't create user and network ns, running on host: %m");
                        _exit(EXIT_FAILURE);
                }

                assert_se(get_process_exe(0, &rt) >= 0);
                assert_se(path_extract_directory(rt, &d) >= 0);

                if (access(d, F_OK) < 0) {
                        log_warning_errno(errno, "test-resolved-stream: Can't access /proc/self/exe from user/network ns, running on host: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }
        if (r == -EPROTO) /* EPROTO means nonzero exit code of child, i.e. the tests in the child failed */
                return;
        assert_se(r > 0);

        /* Now that we know that the unshare() is safe, let's actually do it */
        assert_se(unshare(CLONE_NEWUSER | CLONE_NEWNET) >= 0);

        /* Bring up the loopback interfaceon the newly created network namespace */
        struct ifreq req = { .ifr_ifindex = 1 };
        assert_se((socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) >= 0);
        assert_se(ioctl(socket_fd, SIOCGIFNAME, &req) >= 0);
        assert_se(ioctl(socket_fd, SIOCGIFFLAGS, &req) >= 0);
        assert_se(FLAGS_SET(req.ifr_flags, IFF_LOOPBACK));
        req.ifr_flags |= IFF_UP;
        assert_se(ioctl(socket_fd, SIOCSIFFLAGS, &req) >= 0);
}

int main(int argc, char **argv) {
        server_address = (union sockaddr_union) {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(12345),
                .in.sin_addr.s_addr = htobe32(INADDR_LOOPBACK)
        };

        test_setup_logging(LOG_DEBUG);

        try_isolate_network();

        test_dns_stream(false);
#if ENABLE_DNS_OVER_TLS
        if (system("openssl version >/dev/null 2>&1") != 0)
                return log_tests_skipped("Skipping TLS test since the 'openssl' command does not seem to be available");
        test_dns_stream(true);
#endif

        return 0;
}
