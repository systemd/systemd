/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <string.h>
#include <sys/un.h>

#include "alloc-util.h"
#include "journald-config.h"
#include "log.h"
#include "socket-util.h"
#include "sparse-endian.h"
#include "tests.h"

static void compress_parse_check(const char *str, int expected_enabled, uint64_t expected_threshold) {
        JournalCompressOptions conf = { .enabled = -222, .threshold_bytes = 111 };

        ASSERT_OK(config_parse_compress("", "", 0, "", 0, "", 0, str, &conf, NULL));
        ASSERT_EQ(expected_enabled, conf.enabled);
        if (conf.enabled)
                ASSERT_EQ(expected_threshold, conf.threshold_bytes);
}

TEST(config_compress) {
        compress_parse_check("yes", true, UINT64_MAX);
        compress_parse_check("no", false, UINT64_MAX);
        compress_parse_check("y", true, UINT64_MAX);
        compress_parse_check("n", false, UINT64_MAX);
        compress_parse_check("true", true, UINT64_MAX);
        compress_parse_check("false", false, UINT64_MAX);
        compress_parse_check("t", true, UINT64_MAX);
        compress_parse_check("f", false, UINT64_MAX);
        compress_parse_check("on", true, UINT64_MAX);
        compress_parse_check("off", false, UINT64_MAX);

        /* Weird size/bool overlapping case. We preserve backward compatibility instead of assuming these are byte
         * counts. */
        compress_parse_check("1", true, UINT64_MAX);
        compress_parse_check("0", false, UINT64_MAX);

        /* IEC sizing */
        compress_parse_check("1B", true, 1);
        compress_parse_check("1K", true, 1024);
        compress_parse_check("1M", true, 1024 * 1024);
        compress_parse_check("1G", true, 1024 * 1024 * 1024);

        /* Invalid Case */
        compress_parse_check("-1", -222, 111);
        compress_parse_check("blah blah", -222, 111);
        compress_parse_check("", -1, UINT64_MAX);
}

static void forward_to_socket_parse_check_fails(const char *str) {
        SocketAddress conf = {};

        ASSERT_OK(config_parse_forward_to_socket("", "", 0, "", 0, "", 0, str, &conf, NULL));
        ASSERT_FAIL(socket_address_verify(&conf, true));
}

static void forward_to_socket_parse_check(const char *str, const SocketAddress *expected_addr) {
        _cleanup_free_ char *buf = NULL, *buf2 = NULL;
        SocketAddress conf = {};

        ASSERT_OK(config_parse_forward_to_socket("", "", 0, "", 0, "", 0, str, &conf, NULL));
        ASSERT_OK(socket_address_print(&conf, &buf));
        ASSERT_OK(socket_address_print(expected_addr, &buf2));
        log_info("\"%s\" parsed as \"%s\", should be \"%s\"", str, buf, buf2);
        log_info("socket_address_verify(&expected_addr, false) = %d", socket_address_verify(expected_addr, false));
        log_info("socket_address_verify(&conf, false) = %d", socket_address_verify(&conf, false));
        log_info("socket_address_family(&expected_addr) = %d", socket_address_family(expected_addr));
        log_info("socket_address_family(&conf) = %d", socket_address_family(&conf));
        log_info("expected_addr.size = %u", expected_addr->size);
        log_info("conf.size = %u", conf.size);
        ASSERT_TRUE(socket_address_equal(&conf, expected_addr));
}

TEST(config_forward_to_socket) {
        SocketAddress addr;

        /* Valid AF_UNIX */
        addr = (SocketAddress) {
                .sockaddr.un = (struct sockaddr_un) {
                        .sun_family = AF_UNIX,
                        .sun_path = "/run/host/journal/socket",
                },
                .size = offsetof(struct sockaddr_un, sun_path) + strlen("/run/host/journal/socket") + 1,
        };
        forward_to_socket_parse_check("/run/host/journal/socket", &addr);

        addr.size -= 1;
        memcpy(addr.sockaddr.un.sun_path, "\0run/host/journal/socket", sizeof("\0run/host/journal/socket"));
        forward_to_socket_parse_check("@run/host/journal/socket", &addr);

        /* Valid AF_INET */
        addr = (SocketAddress) {
                .sockaddr.in = (struct sockaddr_in) {
                        .sin_family = AF_INET,
                        .sin_addr = { htobe32(0xC0A80001) },
                        .sin_port = htobe16(1234),
                },
                .size = sizeof(struct sockaddr_in),
        };
        forward_to_socket_parse_check("192.168.0.1:1234", &addr);

        /* Valid AF_INET6 */
        addr = (SocketAddress) {
                .sockaddr.in6 = (struct sockaddr_in6) {
                        .sin6_family = AF_INET6,
                        .sin6_addr = (struct in6_addr) {
                                .s6_addr16 = {
                                        htobe16(0x2001),
                                        htobe16(0xdb8),
                                        htobe16(0x4006),
                                        htobe16(0x812),
                                        0, 0, 0,
                                        htobe16(0x200e)
                                }
                        },
                        .sin6_port = htobe16(8080),
                },
                .size = sizeof(struct sockaddr_in6),
        };
        forward_to_socket_parse_check("[2001:db8:4006:812::200e]:8080", &addr);

        /* Valid AF_VSOCK */
        addr = (SocketAddress) {
                .sockaddr.vm = (struct sockaddr_vm) {
                        .svm_family = AF_VSOCK,
                        .svm_cid = 123456,
                        .svm_port = 654321,
                },
                .size = sizeof(struct sockaddr_vm),
        };
        forward_to_socket_parse_check("vsock:123456:654321", &addr);

        /* Invalid IPv4 */
        forward_to_socket_parse_check_fails("256.123.45.12:1235");
        forward_to_socket_parse_check_fails("252.123.45.12:123500");
        forward_to_socket_parse_check_fails("252.123.45.12:0");
        forward_to_socket_parse_check_fails("252.123.45.12:-1");
        forward_to_socket_parse_check_fails("-1.123.45.12:22");

        /* Invalid IPv6 */
        forward_to_socket_parse_check_fails("[2001:db8:4006:812::200e]:80800");
        forward_to_socket_parse_check_fails("[1ffff:db8:4006:812::200e]:8080");
        forward_to_socket_parse_check_fails("[-1:db8:4006:812::200e]:8080");
        forward_to_socket_parse_check_fails("[2001:db8:4006:812::200e]:-1");

        /* Invalid UNIX */
        forward_to_socket_parse_check_fails("a/b/c");

        /* Invalid VSock */
        forward_to_socket_parse_check_fails("vsock:4294967296:1234");
        forward_to_socket_parse_check_fails("vsock:1234:4294967296");
        forward_to_socket_parse_check_fails("vsock:abcd:1234");
        forward_to_socket_parse_check_fails("vsock:1234:abcd");
        forward_to_socket_parse_check_fails("vsock:1234");

        /* Invalid Case */
        forward_to_socket_parse_check_fails("");
        forward_to_socket_parse_check_fails("ahh yes sockets, mmh");
}

DEFINE_TEST_MAIN(LOG_INFO);
