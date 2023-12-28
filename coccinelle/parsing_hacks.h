/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* FIXME
 *  - issues with parsing stuff like
 *      - validchars = UPPERCASE_LETTERS DIGITS;
 *          - see: https://github.com/coccinelle/coccinelle/issues/341
 *      - keywords in macro invocations like FOREACH_DIRENT_ALL(de, d, return -errno)
 *          - see: https://github.com/coccinelle/coccinelle/issues/340
 *          - also see the FIXME in the TEST() stuff below
 */

/* This file contains parsing hacks for Coccinelle (spatch), to make it happy with some of our more complex
 * macros - it is intended to be used with the --macro-file-builtins option for spatch.
 *
 * Coccinelle's macro support is somewhat limited and the parser trips over some of our more complex macros.
 * In most cases this doesn't really matter, as the parsing errors are silently ignored, but there are
 * special cases in which the parser incorrectly infers information that then causes issues in valid code
 * later down the line.
 *
 * Inspired by a similarly named file [0] from the Coccinelle sources, and the original builtin macros [1].
 *
 * [0] https://github.com/coccinelle/coccinelle/blob/master/parsing_c/parsing_hacks.ml
 * [1] https://github.com/coccinelle/coccinelle/blob/master/standard.h
 *
 */

/* Coccinelle really doesn't like our way of registering unit test cases, and incorrectly assumes that "id"
 * from TEST(id) is the actual function identifier. This then causes name conflicts, since the unit tests
 * are usually named after the functions they test.
 *
 * For example, a unit test for xsetxattr() is defined using TEST(xsetxattr), which eventually yields a
 * procedure with following declaration:
 *
 *      static const void test_xsetxattr(void);
 *
 * However, Coccinelle fails to parse the chain of macros behind TEST(x) and assumes the test function is
 * named "xsetxattr", which then causes a name conflict when the actual "xsetxattr" function is called:
 *
 * (ONCE) SEMANTIC:parameter name omitted, but I continue
 * Warning: PARSING: src/test/test-xattr-util.c:57: type defaults to 'int'; ...
 * ERROR-RECOV: found sync '}' at line 127
 * Parsing pass2: try again
 * ERROR-RECOV: found sync '}' at line 127
 * Parsing pass3: try again
 * ERROR-RECOV: found sync '}' at line 127
 * Parse error
 *  = File "src/test/test-xattr-util.c", line 101, column 12, charpos = 3152
 *   around = 'xsetxattr',
 *   whole content =         r = xsetxattr(AT_FDCWD, x, "user.foo", "fullpath", SIZE_MAX, 0);
 * Badcount: 40
 *
 * The easy way out here is to just provide a simplified version of the TEST(x) macro that pinpoints the most
 * important detail - that the actual function name is prefixed with test_.
 *
 * FIXME: even with this Coccinelle still fails to process TEST(x) instances where x is a keyword, e.g.
 *        TEST(float), TEST(default), ...
 */
#define TEST(x, ...) static void test_##x(void)
#define TEST_RET(x, ...) static int test_##x(void)

/* Coccinelle doesn't know this keyword, so just drop it, since it's not important for any of our rules. */
#define thread_local

/* Coccinelle fails to parse these from the included headers, so let's just drop them. */
#define PAM_EXTERN
#define STACK_OF(x)

/* Mark a couple of iterator explicitly as iterators, otherwise Coccinelle gets a bit confused. Coccinelle
 * can usually infer this information automagically, but in these specific cases it needs a bit of help. */
#define FOREACH_ARRAY(i, array, num) YACFE_ITERATOR
#define FOREACH_DIRENT_ALL(de, d, on_error) YACFE_ITERATOR
#define FOREACH_STRING(x, y, ...) YACFE_ITERATOR
#define HASHMAP_FOREACH(e, h) YACFE_ITERATOR
#define LIST_FOREACH(name, i, head) YACFE_ITERATOR
#define ORDERED_HASHMAP_FOREACH(e, h) YACFE_ITERATOR
#define SET_FOREACH(e, s) YACFE_ITERATOR
#define STRV_FOREACH_BACKWARDS YACFE_ITERATOR

/* Coccinelle really doesn't like multiline macros that are not in the "usual" do { ... } while(0) format, so
 * let's help it a little here by providing simplified one-line versions. */
#define CMSG_BUFFER_TYPE(x) union { uint8_t align_check[(size) >= CMSG_SPACE(0) && (size) == CMSG_ALIGN(size) ? 1 : -1]; }
#define SD_ID128_MAKE(...) ((const sd_id128) {})
