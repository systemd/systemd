/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "tests.h"
#include "wall.h"

TEST(wall_sanitize_message_plain) {
        _cleanup_free_ char *s = NULL;

        /* Ordinary text, whitespace, and UTF-8 must pass through unchanged. */
        assert_se(s = wall_sanitize_message("The system is going down for poweroff NOW!"));
        ASSERT_STREQ(s, "The system is going down for poweroff NOW!");
        s = mfree(s);

        assert_se(s = wall_sanitize_message("line1\tindented\nline2\r\nline3"));
        ASSERT_STREQ(s, "line1\tindented\nline2\r\nline3");
        s = mfree(s);

        assert_se(s = wall_sanitize_message("Grüße — 日本語"));
        ASSERT_STREQ(s, "Grüße — 日本語");
        s = mfree(s);

        assert_se(s = wall_sanitize_message(""));
        ASSERT_STREQ(s, "");
}

TEST(wall_sanitize_message_ansi) {
        _cleanup_free_ char *s = NULL;

        /* SGR color sequences. */
        assert_se(s = wall_sanitize_message("\x1B[1;31mRED\x1B[0m plain"));
        ASSERT_STREQ(s, "RED plain");
        s = mfree(s);

        /* Cursor movement and screen clearing. */
        assert_se(s = wall_sanitize_message("a\x1B[2J\x1B[Hb"));
        ASSERT_STREQ(s, "ab");
        s = mfree(s);

        /* Window manipulation (a classic terminal-emulator exploit vector). */
        assert_se(s = wall_sanitize_message("a\x1B[2;100tb"));
        ASSERT_STREQ(s, "ab");
        s = mfree(s);

        /* Single-byte CSI (U+009B) encoded in UTF-8. */
        assert_se(s = wall_sanitize_message("a\xc2\x9b" "31mb"));
        ASSERT_STREQ(s, "a31mb");
        s = mfree(s);

        /* Truncated CSI at end of string must not leak ESC bytes. */
        assert_se(s = wall_sanitize_message("a\x1B[31"));
        ASSERT_STREQ(s, "a");
        s = mfree(s);

        /* Unknown two-character sequence: ESC and follower are swallowed, like terminals do. */
        assert_se(s = wall_sanitize_message("a\x1B" "b"));
        ASSERT_STREQ(s, "a");
        s = mfree(s);
}

TEST(wall_sanitize_message_osc) {
        _cleanup_free_ char *s = NULL;

        /* OSC hyperlink terminated by BEL. */
        assert_se(s = wall_sanitize_message("click \x1B]8;;https://example.invalid/\aHERE\x1B]8;;\a!"));
        ASSERT_STREQ(s, "click HERE!");
        s = mfree(s);

        /* OSC hyperlink terminated by ST. */
        assert_se(s = wall_sanitize_message("a\x1B]8;;https://example.invalid/\x1B\\b"));
        ASSERT_STREQ(s, "ab");
        s = mfree(s);

        /* Unterminated OSC consumes the rest of the message. */
        assert_se(s = wall_sanitize_message("a\x1B]8;;https://example.invalid/"));
        ASSERT_STREQ(s, "a");
}

TEST(wall_sanitize_message_controls) {
        _cleanup_free_ char *s = NULL;

        /* C0 controls (other than tab/LF/CR, incl. BEL) and DEL are dropped. */
        assert_se(s = wall_sanitize_message("a\x01" "b\x07" "c\bd\x0b" "e\x0c" "f"));
        ASSERT_STREQ(s, "abcdef");
        s = mfree(s);

        assert_se(s = wall_sanitize_message("a\x7F" "b"));
        ASSERT_STREQ(s, "ab");
        s = mfree(s);

        /* Invalid bytes are dropped, valid UTF-8 around them is kept. */
        assert_se(s = wall_sanitize_message("a\xff\xfe" "b\xc3"));
        ASSERT_STREQ(s, "ab");
        s = mfree(s);

        /* Two-character escape sequences are swallowed; inert remainders stay. */
        assert_se(s = wall_sanitize_message("a\x1B" "7b" "\x1B" "cc"));
        ASSERT_STREQ(s, "abc");
        s = mfree(s);
}

DEFINE_TEST_MAIN(LOG_INFO);
