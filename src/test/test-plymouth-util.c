/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "plymouth-util.h"
#include "strv.h"
#include "tests.h"

TEST(build_password_packet) {
        _cleanup_free_ char *packet = NULL;
        size_t size;

        ASSERT_OK(plymouth_build_password_packet("Password:", &packet, &size));
        ASSERT_EQ(size, 13U);
        ASSERT_EQ(memcmp(packet, "*\x02\x0aPassword:\0", size), 0);

        packet = mfree(packet);

        char message[UCHAR_MAX];
        memset(message, 'x', sizeof(message) - 1);
        message[sizeof(message) - 1] = '\0';

        ASSERT_OK(plymouth_build_password_packet(message, &packet, &size));
        ASSERT_EQ(size, 3U + sizeof(message));
        ASSERT_EQ((uint8_t) packet[2], UCHAR_MAX);
        ASSERT_EQ(memcmp(packet + 3, message, sizeof(message)), 0);

        packet = mfree(packet);
        ASSERT_ERROR(plymouth_build_password_packet(strjoina(message, "x"), &packet, &size), EMSGSIZE);
        ASSERT_NULL(packet);
}

TEST(parse_password_reply) {
        _cleanup_strv_free_ char **reply = NULL;

        ASSERT_NOT_NULL(reply = plymouth_parse_password_reply(2, "", 0));
        ASSERT_TRUE(strv_equal(reply, STRV_MAKE("")));
        reply = strv_free(reply);

        ASSERT_NOT_NULL(reply = plymouth_parse_password_reply(9, "", 0));
        ASSERT_TRUE(strv_isempty(reply));
        reply = strv_free(reply);

        ASSERT_NOT_NULL(reply = plymouth_parse_password_reply(2, "", 1));
        ASSERT_TRUE(strv_equal(reply, STRV_MAKE("")));
        reply = strv_free(reply);

        ASSERT_NOT_NULL(reply = plymouth_parse_password_reply(2, "password", sizeof("password")));
        ASSERT_TRUE(strv_equal(reply, STRV_MAKE("password")));
        reply = strv_free(reply);

        ASSERT_NOT_NULL(reply = plymouth_parse_password_reply(9, "one\0two", sizeof("one\0two")));
        ASSERT_TRUE(strv_equal(reply, STRV_MAKE("one", "two")));
}

DEFINE_TEST_MAIN(LOG_INFO);
