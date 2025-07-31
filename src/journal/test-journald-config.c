/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <string.h>
#include <sys/un.h>

#include "alloc-util.h"
#include "journald-manager.h"
#include "log.h"
#include "socket-util.h"
#include "sparse-endian.h"
#include "tests.h"

#define _COMPRESS_PARSE_CHECK(str, enab, thresh, varname)               \
        do {                                                            \
                JournalCompressOptions varname = {-222, 111};           \
                config_parse_compress("", "", 0, "", 0, "", 0, str,     \
                                      &varname, NULL);                  \
                assert_se((enab) == varname.enabled);                   \
                if (varname.enabled)                                    \
                        assert_se((thresh) == varname.threshold_bytes); \
        } while (0)

#define COMPRESS_PARSE_CHECK(str, enabled, threshold)                   \
        _COMPRESS_PARSE_CHECK(str, enabled, threshold, conf##__COUNTER__)

TEST(config_compress) {
        COMPRESS_PARSE_CHECK("yes", true, UINT64_MAX);
        COMPRESS_PARSE_CHECK("no", false, UINT64_MAX);
        COMPRESS_PARSE_CHECK("y", true, UINT64_MAX);
        COMPRESS_PARSE_CHECK("n", false, UINT64_MAX);
        COMPRESS_PARSE_CHECK("true", true, UINT64_MAX);
        COMPRESS_PARSE_CHECK("false", false, UINT64_MAX);
        COMPRESS_PARSE_CHECK("t", true, UINT64_MAX);
        COMPRESS_PARSE_CHECK("f", false, UINT64_MAX);
        COMPRESS_PARSE_CHECK("on", true, UINT64_MAX);
        COMPRESS_PARSE_CHECK("off", false, UINT64_MAX);

        /* Weird size/bool overlapping case. We preserve backward compatibility instead of assuming these are byte
         * counts. */
        COMPRESS_PARSE_CHECK("1", true, UINT64_MAX);
        COMPRESS_PARSE_CHECK("0", false, UINT64_MAX);

        /* IEC sizing */
        COMPRESS_PARSE_CHECK("1B", true, 1);
        COMPRESS_PARSE_CHECK("1K", true, 1024);
        COMPRESS_PARSE_CHECK("1M", true, 1024 * 1024);
        COMPRESS_PARSE_CHECK("1G", true, 1024 * 1024 * 1024);

        /* Invalid Case */
        COMPRESS_PARSE_CHECK("-1", -222, 111);
        COMPRESS_PARSE_CHECK("blah blah", -222, 111);
        COMPRESS_PARSE_CHECK("", -1, UINT64_MAX);
}

#define _FORWARD_TO_SOCKET_PARSE_CHECK_FAILS(str, addr, varname)             \
        do {                                                                 \
                SocketAddress varname = {};                                  \
                config_parse_forward_to_socket("", "", 0, "", 0, "", 0, str, \
                                               &varname, NULL);              \
                assert_se(socket_address_verify(&varname, true) < 0);        \
        } while (0)

#define FORWARD_TO_SOCKET_PARSE_CHECK_FAILS(str) \
        _FORWARD_TO_SOCKET_PARSE_CHECK_FAILS(str, addr, conf##__COUNTER__)

#define _FORWARD_TO_SOCKET_PARSE_CHECK(str, addr, varname)                   \
        do {                                                                 \
                SocketAddress varname = {};                                  \
                config_parse_forward_to_socket("", "", 0, "", 0, "", 0, str, \
                                               &varname, NULL);              \
                buf = mfree(buf);                                            \
                buf2 = mfree(buf2);                                          \
                socket_address_print(&varname, &buf);                        \
                socket_address_print(&addr, &buf2);                          \
                log_info("\"%s\" parsed as \"%s\", should be \"%s\"", str, buf, buf2); \
                log_info("socket_address_verify(&addr, false) = %d", socket_address_verify(&addr, false)); \
                log_info("socket_address_verify(&varname, false) = %d", socket_address_verify(&varname, false)); \
                log_info("socket_address_family(&addr) = %d", socket_address_family(&addr)); \
                log_info("socket_address_family(&varname) = %d", socket_address_family(&varname)); \
                log_info("addr.size = %u", addr.size);                       \
                log_info("varname.size = %u", varname.size);                 \
                assert_se(socket_address_equal(&varname, &addr));            \
        } while (0)

#define FORWARD_TO_SOCKET_PARSE_CHECK(str, addr)                     \
        _FORWARD_TO_SOCKET_PARSE_CHECK(str, addr, conf##__COUNTER__)

TEST(config_forward_to_socket) {
        SocketAddress addr;
        _cleanup_free_ char *buf = NULL, *buf2 = NULL;

        /* Valid AF_UNIX */
        addr = (SocketAddress) {
                .sockaddr.un = (struct sockaddr_un) {
                        .sun_family = AF_UNIX,
                        .sun_path = "/run/host/journal/socket",
                },
                .size = offsetof(struct sockaddr_un, sun_path) + strlen("/run/host/journal/socket") + 1,
        };
        FORWARD_TO_SOCKET_PARSE_CHECK("/run/host/journal/socket", addr);

        addr.size -= 1;
        memcpy(addr.sockaddr.un.sun_path, "\0run/host/journal/socket", sizeof("\0run/host/journal/socket"));
        FORWARD_TO_SOCKET_PARSE_CHECK("@run/host/journal/socket", addr);

        /* Valid AF_INET */
        addr = (SocketAddress) {
                .sockaddr.in = (struct sockaddr_in) {
                        .sin_family = AF_INET,
                        .sin_addr = { htobe32(0xC0A80001) },
                        .sin_port = htobe16(1234),
                },
                .size = sizeof(struct sockaddr_in),
        };
        FORWARD_TO_SOCKET_PARSE_CHECK("192.168.0.1:1234", addr);

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
        FORWARD_TO_SOCKET_PARSE_CHECK("[2001:db8:4006:812::200e]:8080", addr);

        /* Valid AF_VSOCK */
        addr = (SocketAddress) {
                .sockaddr.vm = (struct sockaddr_vm) {
                        .svm_family = AF_VSOCK,
                        .svm_cid = 123456,
                        .svm_port = 654321,
                },
                .size = sizeof(struct sockaddr_vm),
        };
        FORWARD_TO_SOCKET_PARSE_CHECK("vsock:123456:654321", addr);

        /* Invalid IPv4 */
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("256.123.45.12:1235");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("252.123.45.12:123500");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("252.123.45.12:0");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("252.123.45.12:-1");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("-1.123.45.12:22");

        /* Invalid IPv6 */
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("[2001:db8:4006:812::200e]:80800");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("[1ffff:db8:4006:812::200e]:8080");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("[-1:db8:4006:812::200e]:8080");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("[2001:db8:4006:812::200e]:-1");

        /* Invalid UNIX */
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("a/b/c");

        /* Invalid VSock */
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("vsock:4294967296:1234");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("vsock:1234:4294967296");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("vsock:abcd:1234");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("vsock:1234:abcd");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("vsock:1234");

        /* Invalid Case */
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("");
        FORWARD_TO_SOCKET_PARSE_CHECK_FAILS("ahh yes sockets, mmh");
}

DEFINE_TEST_MAIN(LOG_INFO);
