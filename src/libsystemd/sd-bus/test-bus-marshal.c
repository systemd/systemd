/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>

/* We make an exception here to our usual "include system headers first" rule because we need one of these
 * macros to disable a warning triggered by the glib headers. */
#include "macro-fundamental.h"

#if HAVE_GLIB
DISABLE_WARNING_FORMAT_NONLITERAL
#include <gio/gio.h> /* NOLINT */
REENABLE_WARNING
#endif

#if HAVE_DBUS
#include <dbus/dbus.h>
#endif

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-util.h"
#include "escape.h"
#include "log.h"
#include "memstream-util.h"
#include "tests.h"

static void test_bus_path_encode_unique(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;

        assert_se(bus_path_encode_unique(NULL, "/foo/bar", "some.sender", "a.suffix", &a) >= 0 && streq_ptr(a, "/foo/bar/some_2esender/a_2esuffix"));
        assert_se(bus_path_decode_unique(a, "/foo/bar", &b, &c) > 0 && streq_ptr(b, "some.sender") && streq_ptr(c, "a.suffix"));
        assert_se(bus_path_decode_unique(a, "/bar/foo", &d, &d) == 0 && !d);
        assert_se(bus_path_decode_unique("/foo/bar/onlyOneSuffix", "/foo/bar", &d, &d) == 0 && !d);
        assert_se(bus_path_decode_unique("/foo/bar/_/_", "/foo/bar", &d, &e) > 0 && streq_ptr(d, "") && streq_ptr(e, ""));
}

static void test_bus_path_encode(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL;

        assert_se(sd_bus_path_encode("/foo/bar", "waldo", &a) >= 0 && streq(a, "/foo/bar/waldo"));
        assert_se(sd_bus_path_decode(a, "/waldo", &b) == 0 && b == NULL);
        assert_se(sd_bus_path_decode(a, "/foo/bar", &b) > 0 && streq(b, "waldo"));

        ASSERT_RETURN_EXPECTED_SE(sd_bus_path_encode("xxxx", "waldo", &c) < 0);
        ASSERT_RETURN_EXPECTED_SE(sd_bus_path_encode("/foo/", "waldo", &c) < 0);

        assert_se(sd_bus_path_encode("/foo/bar", "", &c) >= 0 && streq(c, "/foo/bar/_"));
        assert_se(sd_bus_path_decode(c, "/foo/bar", &d) > 0 && streq(d, ""));

        assert_se(sd_bus_path_encode("/foo/bar", "foo.bar", &e) >= 0 && streq(e, "/foo/bar/foo_2ebar"));
        assert_se(sd_bus_path_decode(e, "/foo/bar", &f) > 0 && streq(f, "foo.bar"));

        assert_se(sd_bus_path_decode("/waldo", "/waldo", &g) > 0 && streq(g, ""));
}

static void test_bus_path_encode_many(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL;

        assert_se(sd_bus_path_decode_many("/foo/bar", "/prefix/%", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/prefix/bar", "/prefix/%bar", NULL) == 1);
        assert_se(sd_bus_path_decode_many("/foo/bar", "/prefix/%/suffix", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/prefix/foobar/suffix", "/prefix/%/suffix", &a) == 1 && streq_ptr(a, "foobar"));
        assert_se(sd_bus_path_decode_many("/prefix/one_foo_two/mid/three_bar_four/suffix", "/prefix/one_%_two/mid/three_%_four/suffix", &b, &c) == 1 && streq_ptr(b, "foo") && streq_ptr(c, "bar"));
        assert_se(sd_bus_path_decode_many("/prefix/one_foo_two/mid/three_bar_four/suffix", "/prefix/one_%_two/mid/three_%_four/suffix", NULL, &d) == 1 && streq_ptr(d, "bar"));

        assert_se(sd_bus_path_decode_many("/foo/bar", "/foo/bar/%", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/bar%", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/bar", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%bar", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/bar/suffix") == 1);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%%/suffix", NULL, NULL) == 0); /* multiple '%' are treated verbatim */
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/suffi", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/suffix", &e) == 1 && streq_ptr(e, "bar"));
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/%", NULL, NULL) == 1);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/%/%/%", NULL, NULL, NULL) == 1);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "%/%/%", NULL, NULL, NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/%/%", NULL, NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/%/%/", NULL, NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/%/", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "/%", NULL) == 0);
        assert_se(sd_bus_path_decode_many("/foo/bar/suffix", "%", NULL) == 0);

        assert_se(sd_bus_path_encode_many(&f, "/prefix/one_%_two/mid/three_%_four/suffix", "foo", "bar") >= 0 && streq_ptr(f, "/prefix/one_foo_two/mid/three_bar_four/suffix"));
}

static void test_bus_label_escape_one(const char *a, const char *b) {
        _cleanup_free_ char *t = NULL, *x = NULL, *y = NULL;

        assert_se(t = bus_label_escape(a));
        assert_se(streq(t, b));

        assert_se(x = bus_label_unescape(t));
        assert_se(streq(a, x));

        assert_se(y = bus_label_unescape(b));
        assert_se(streq(a, y));
}

static void test_bus_label_escape(void) {
        test_bus_label_escape_one("foo123bar", "foo123bar");
        test_bus_label_escape_one("foo.bar", "foo_2ebar");
        test_bus_label_escape_one("foo_2ebar", "foo_5f2ebar");
        test_bus_label_escape_one("", "_");
        test_bus_label_escape_one("_", "_5f");
        test_bus_label_escape_one("1", "_31");
        test_bus_label_escape_one(":1", "_3a1");
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *copy = NULL;
        _cleanup_free_ char *h = NULL, *first = NULL, *second = NULL, *third = NULL;
        const int32_t integer_array[] = { -1, -2, 0, 1, 2 }, *return_array;
        const char *x, *x2, *y, *z, *a, *b, *c, *d, *a_signature;
        size_t sz, first_size, second_size = 0, third_size = 0;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(memstream_done) MemStream ms = {};
        void *buffer = NULL;
        int r, boolean;
        uint64_t u64;
        uint8_t u, v;
        double dbl;
        FILE *mf;
        char *s;

        test_setup_logging(LOG_INFO);

        r = sd_bus_default_user(&bus);
        if (r < 0)
                r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_tests_skipped("Failed to connect to bus");

        r = sd_bus_message_new_method_call(bus, &m, "foobar.waldo", "/", "foobar.waldo", "Piep");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "s", "a string");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "s", NULL);
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "asg", 2, "string #1", "string #2", "sba(tt)ss");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "sass", "foobar", 5, "foo", "bar", "waldo", "piep", "pap", "after");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "a{yv}", 2, 3, "s", "foo", 5, "s", "waldo");
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "y(ty)y(yt)y", 8, 777ULL, 7, 9, 77, 7777ULL, 10);
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "()");
        assert_se(r == -EINVAL);

        r = sd_bus_message_append(m, "ba(ss)", 255, 3, "aaa", "1", "bbb", "2", "ccc", "3");
        assert_se(r >= 0);

        r = sd_bus_message_open_container(m, 'a', "s");
        assert_se(r >= 0);

        r = sd_bus_message_append_basic(m, 's', "foobar");
        assert_se(r >= 0);

        r = sd_bus_message_append_basic(m, 's', "waldo");
        assert_se(r >= 0);

        r = sd_bus_message_close_container(m);
        assert_se(r >= 0);

        r = sd_bus_message_append_string_space(m, 5, &s);
        assert_se(r >= 0);
        strcpy(s, "hallo");

        r = sd_bus_message_append_array(m, 'i', integer_array, sizeof(integer_array));
        assert_se(r >= 0);

        r = sd_bus_message_append_array(m, 'u', NULL, 0);
        assert_se(r >= 0);

        r = sd_bus_message_append(m, "a(stdo)", 1, "foo", 815ULL, 47.0, "/");
        assert_se(r >= 0);

        r = sd_bus_message_seal(m, 4711, 0);
        assert_se(r >= 0);

        sd_bus_message_dump(m, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        assert_se(mf = memstream_init(&ms));
        sd_bus_message_dump(m, mf, 0);
        assert_se(memstream_finalize(&ms, &first, &first_size) >= 0);

        r = bus_message_get_blob(m, &buffer, &sz);
        assert_se(r >= 0);

        h = cescape_length(buffer, sz);
        assert_se(h);
        log_info("message size = %zu, contents =\n%s", sz, h);

#if HAVE_GLIB
        /* Work-around for asan bug. See c8d980a3e962aba2ea3a4cedf75fa94890a6d746. */
#if !HAS_FEATURE_ADDRESS_SANITIZER
        {
                GDBusMessage *g;
                char *p;

#if !defined(GLIB_VERSION_2_36)
                g_type_init();
#endif

                g = g_dbus_message_new_from_blob(buffer, sz, 0, NULL);
                p = g_dbus_message_print(g, 0);
                log_info("%s", p);
                g_free(p);
                g_object_unref(g);
        }
#endif
#endif

#if HAVE_DBUS
        {
                DBusMessage *w;
                DBusError error;

                dbus_error_init(&error);

                w = dbus_message_demarshal(buffer, sz, &error);
                if (!w)
                        log_error("%s", error.message);
                else
                        dbus_message_unref(w);

                dbus_error_free(&error);
        }
#endif

        m = sd_bus_message_unref(m);

        r = bus_message_from_malloc(bus, buffer, sz, NULL, 0, NULL, &m);
        assert_se(r >= 0);

        sd_bus_message_dump(m, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        assert_se(mf = memstream_init(&ms));
        sd_bus_message_dump(m, mf, 0);
        assert_se(memstream_finalize(&ms, &second, &second_size) >= 0);
        assert_se(first_size == second_size);
        assert_se(memcmp(first, second, first_size) == 0);

        assert_se(sd_bus_message_rewind(m, true) >= 0);

        r = sd_bus_message_read(m, "ssasg", &x, &x2, 2, &y, &z, &a_signature);
        assert_se(r > 0);
        assert_se(streq(x, "a string"));
        assert_se(streq(x2, ""));
        assert_se(streq(y, "string #1"));
        assert_se(streq(z, "string #2"));
        assert_se(streq(a_signature, "sba(tt)ss"));

        r = sd_bus_message_read(m, "sass", &x, 5, &y, &z, &a, &b, &c, &d);
        assert_se(r > 0);
        assert_se(streq(x, "foobar"));
        assert_se(streq(y, "foo"));
        assert_se(streq(z, "bar"));
        assert_se(streq(a, "waldo"));
        assert_se(streq(b, "piep"));
        assert_se(streq(c, "pap"));
        assert_se(streq(d, "after"));

        r = sd_bus_message_read(m, "a{yv}", 2, &u, "s", &x, &v, "s", &y);
        assert_se(r > 0);
        assert_se(u == 3);
        assert_se(streq(x, "foo"));
        assert_se(v == 5);
        assert_se(streq(y, "waldo"));

        r = sd_bus_message_read(m, "y(ty)", &v, &u64, &u);
        assert_se(r > 0);
        assert_se(v == 8);
        assert_se(u64 == 777);
        assert_se(u == 7);

        r = sd_bus_message_read(m, "y(yt)", &v, &u, &u64);
        assert_se(r > 0);
        assert_se(v == 9);
        assert_se(u == 77);
        assert_se(u64 == 7777);

        r = sd_bus_message_read(m, "y", &v);
        assert_se(r > 0);
        assert_se(v == 10);

        r = sd_bus_message_read(m, "()");
        assert_se(r < 0);

        r = sd_bus_message_read(m, "ba(ss)", &boolean, 3, &x, &y, &a, &b, &c, &d);
        assert_se(r > 0);
        assert_se(boolean);
        assert_se(streq(x, "aaa"));
        assert_se(streq(y, "1"));
        assert_se(streq(a, "bbb"));
        assert_se(streq(b, "2"));
        assert_se(streq(c, "ccc"));
        assert_se(streq(d, "3"));

        assert_se(sd_bus_message_verify_type(m, 'a', "s") > 0);

        r = sd_bus_message_read(m, "as", 2, &x, &y);
        assert_se(r > 0);
        assert_se(streq(x, "foobar"));
        assert_se(streq(y, "waldo"));

        r = sd_bus_message_read_basic(m, 's', &s);
        assert_se(r > 0);
        assert_se(streq(s, "hallo"));

        r = sd_bus_message_read_array(m, 'i', (const void**) &return_array, &sz);
        assert_se(r > 0);
        assert_se(sz == sizeof(integer_array));
        assert_se(memcmp(integer_array, return_array, sz) == 0);

        r = sd_bus_message_read_array(m, 'u', (const void**) &return_array, &sz);
        assert_se(r > 0);
        assert_se(sz == 0);

        r = sd_bus_message_read(m, "a(stdo)", 1, &x, &u64, &dbl, &y);
        assert_se(r > 0);
        assert_se(streq(x, "foo"));
        assert_se(u64 == 815ULL);
        assert_se(fabs(dbl - 47.0) < 0.1);
        assert_se(streq(y, "/"));

        r = sd_bus_message_peek_type(m, NULL, NULL);
        assert_se(r == 0);

        r = sd_bus_message_new_method_call(bus, &copy, "foobar.waldo", "/", "foobar.waldo", "Piep");
        assert_se(r >= 0);

        r = sd_bus_message_rewind(m, true);
        assert_se(r >= 0);

        r = sd_bus_message_copy(copy, m, true);
        assert_se(r >= 0);

        r = sd_bus_message_seal(copy, 4712, 0);
        assert_se(r >= 0);

        assert_se(mf = memstream_init(&ms));
        sd_bus_message_dump(copy, mf, 0);
        assert_se(memstream_finalize(&ms, &third, &third_size) >= 0);

        printf("<%.*s>\n", (int) first_size, first);
        printf("<%.*s>\n", (int) third_size, third);

        assert_se(first_size == third_size);
        assert_se(memcmp(first, third, third_size) == 0);

        r = sd_bus_message_rewind(m, true);
        assert_se(r >= 0);

        assert_se(sd_bus_message_verify_type(m, 's', NULL) > 0);

        r = sd_bus_message_skip(m, "ssasg");
        assert_se(r > 0);

        assert_se(sd_bus_message_verify_type(m, 's', NULL) > 0);

        r = sd_bus_message_skip(m, "sass");
        assert_se(r >= 0);

        assert_se(sd_bus_message_verify_type(m, 'a', "{yv}") > 0);

        r = sd_bus_message_skip(m, "a{yv}y(ty)y(yt)y");
        assert_se(r >= 0);

        assert_se(sd_bus_message_verify_type(m, 'b', NULL) > 0);

        r = sd_bus_message_read(m, "b", &boolean);
        assert_se(r > 0);
        assert_se(boolean);

        r = sd_bus_message_enter_container(m, 0, NULL);
        assert_se(r > 0);

        r = sd_bus_message_read(m, "(ss)", &x, &y);
        assert_se(r > 0);

        r = sd_bus_message_read(m, "(ss)", &a, &b);
        assert_se(r > 0);

        r = sd_bus_message_read(m, "(ss)", &c, &d);
        assert_se(r > 0);

        r = sd_bus_message_read(m, "(ss)", &x, &y);
        assert_se(r == 0);

        r = sd_bus_message_exit_container(m);
        assert_se(r >= 0);

        assert_se(streq(x, "aaa"));
        assert_se(streq(y, "1"));
        assert_se(streq(a, "bbb"));
        assert_se(streq(b, "2"));
        assert_se(streq(c, "ccc"));
        assert_se(streq(d, "3"));

        test_bus_label_escape();
        test_bus_path_encode();
        test_bus_path_encode_unique();
        test_bus_path_encode_many();

        return 0;
}
