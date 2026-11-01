/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* We make an exception here to our usual "include system headers first" rule because we need one of these
 * macros to disable a warning triggered by the glib headers. */
#include "macro.h"

#if HAVE_GLIB
#ifndef SYSTEMD_CFLAGS_MARKER_LIBGLIB
#  error "missing libglib_cflags in meson dependency."
#endif
DISABLE_WARNING_FORMAT_NONLITERAL
#include <gio/gio.h> /* NOLINT */
REENABLE_WARNING
#endif

#if HAVE_DBUS
#ifndef SYSTEMD_CFLAGS_MARKER_LIBDBUS
#  error "missing libdbus_cflags in meson dependency."
#endif
#include <dbus/dbus.h>
#endif

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-util.h"
#include "dlfcn-util.h"
#include "escape.h"
#include "fd-util.h"
#include "log.h"
#include "memfd-util.h"
#include "memstream-util.h"
#include "stat-util.h"
#include "tests.h"

#if HAVE_GLIB
static DLSYM_PROTOTYPE(g_dbus_message_new_from_blob) = NULL;
static DLSYM_PROTOTYPE(g_dbus_message_print)         = NULL;
static DLSYM_PROTOTYPE(g_free)                       = NULL;
static DLSYM_PROTOTYPE(g_object_unref)               = NULL;

static int dlopen_glib(void) {
        static void *glib_dl = NULL;

        return dlopen_many_sym_or_warn(
                        &glib_dl, "libgio-2.0.so.0", LOG_DEBUG,
                        DLSYM_ARG(g_dbus_message_new_from_blob),
                        DLSYM_ARG(g_dbus_message_print),
                        DLSYM_ARG(g_free),
                        DLSYM_ARG(g_object_unref));
}
#endif

#if HAVE_DBUS
static DLSYM_PROTOTYPE(dbus_error_init)        = NULL;
static DLSYM_PROTOTYPE(dbus_error_free)        = NULL;
static DLSYM_PROTOTYPE(dbus_message_demarshal) = NULL;
static DLSYM_PROTOTYPE(dbus_message_unref)     = NULL;

static int dlopen_libdbus(void) {
        static void *libdbus_dl = NULL;

        return dlopen_many_sym_or_warn(
                        &libdbus_dl, "libdbus-1.so.3", LOG_DEBUG,
                        DLSYM_ARG(dbus_error_init),
                        DLSYM_ARG(dbus_error_free),
                        DLSYM_ARG(dbus_message_demarshal),
                        DLSYM_ARG(dbus_message_unref));
}
#endif

static void test_bus_path_encode_unique(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL;

        ASSERT_OK(bus_path_encode_unique(NULL, "/foo/bar", "some.sender", "a.suffix", &a));
        ASSERT_STREQ(a, "/foo/bar/some_2esender/a_2esuffix");
        ASSERT_OK_POSITIVE(bus_path_decode_unique(a, "/foo/bar", &b, &c));
        ASSERT_STREQ(b, "some.sender");
        ASSERT_STREQ(c, "a.suffix");
        ASSERT_OK_EQ(bus_path_decode_unique(a, "/bar/foo", &d, &d), 0);
        ASSERT_NULL(d);
        ASSERT_OK_EQ(bus_path_decode_unique("/foo/bar/onlyOneSuffix", "/foo/bar", &d, &d), 0);
        ASSERT_NULL(d);
        ASSERT_OK_POSITIVE(bus_path_decode_unique("/foo/bar/_/_", "/foo/bar", &d, &e));
        ASSERT_STREQ(d, "");
        ASSERT_STREQ(e, "");
}

static void test_bus_path_encode(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL;

        ASSERT_OK(sd_bus_path_encode("/foo/bar", "waldo", &a));
        ASSERT_STREQ(a, "/foo/bar/waldo");
        ASSERT_OK_EQ(sd_bus_path_decode(a, "/waldo", &b), 0);
        ASSERT_NULL(b);
        ASSERT_OK_POSITIVE(sd_bus_path_decode(a, "/foo/bar", &b));
        ASSERT_STREQ(b, "waldo");

        ASSERT_RETURN_EXPECTED(ASSERT_FAIL(sd_bus_path_encode("xxxx", "waldo", &c)));
        ASSERT_RETURN_EXPECTED(ASSERT_FAIL(sd_bus_path_encode("/foo/", "waldo", &c)));

        ASSERT_OK(sd_bus_path_encode("/foo/bar", "", &c));
        ASSERT_STREQ(c, "/foo/bar/_");
        ASSERT_OK_POSITIVE(sd_bus_path_decode(c, "/foo/bar", &d));
        ASSERT_STREQ(d, "");

        ASSERT_OK(sd_bus_path_encode("/foo/bar", "foo.bar", &e));
        ASSERT_STREQ(e, "/foo/bar/foo_2ebar");
        ASSERT_OK_POSITIVE(sd_bus_path_decode(e, "/foo/bar", &f));
        ASSERT_STREQ(f, "foo.bar");

        ASSERT_OK_POSITIVE(sd_bus_path_decode("/waldo", "/waldo", &g));
        ASSERT_STREQ(g, "");
}

static void test_bus_path_encode_many(void) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL;

        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar", "/prefix/%", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/prefix/bar", "/prefix/%bar", NULL), 1);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar", "/prefix/%/suffix", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/prefix/foobar/suffix", "/prefix/%/suffix", &a), 1);
        ASSERT_STREQ(a, "foobar");
        ASSERT_OK_EQ(sd_bus_path_decode_many("/prefix/one_foo_two/mid/three_bar_four/suffix", "/prefix/one_%_two/mid/three_%_four/suffix", &b, &c), 1);
        ASSERT_STREQ(b, "foo");
        ASSERT_STREQ(c, "bar");
        ASSERT_OK_EQ(sd_bus_path_decode_many("/prefix/one_foo_two/mid/three_bar_four/suffix", "/prefix/one_%_two/mid/three_%_four/suffix", NULL, &d), 1);
        ASSERT_STREQ(d, "bar");

        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar", "/foo/bar/%", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/bar%", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/bar", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%bar", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/bar/suffix"), 1);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%%/suffix", NULL, NULL), 0); /* multiple '%' are treated verbatim */
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/suffi", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/suffix", &e), 1);
        ASSERT_STREQ(e, "bar");
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/foo/%/%", NULL, NULL), 1);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/%/%/%", NULL, NULL, NULL), 1);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "%/%/%", NULL, NULL, NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/%/%", NULL, NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/%/%/", NULL, NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/%/", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "/%", NULL), 0);
        ASSERT_OK_EQ(sd_bus_path_decode_many("/foo/bar/suffix", "%", NULL), 0);

        ASSERT_OK(sd_bus_path_encode_many(&f, "/prefix/one_%_two/mid/three_%_four/suffix", "foo", "bar"));
        ASSERT_STREQ(f, "/prefix/one_foo_two/mid/three_bar_four/suffix");
}

static void test_bus_label_escape_one(const char *a, const char *b) {
        _cleanup_free_ char *t = NULL, *x = NULL, *y = NULL;

        ASSERT_NOT_NULL(t = bus_label_escape(a));
        ASSERT_STREQ(t, b);

        ASSERT_NOT_NULL(x = bus_label_unescape(t));
        ASSERT_STREQ(a, x);

        ASSERT_NOT_NULL(y = bus_label_unescape(b));
        ASSERT_STREQ(a, y);
}

static ino_t get_inode(int fd) {
        struct stat st;
        ASSERT_OK_ERRNO(fstat(fd, &st));
        return st.st_ino;
}

static void test_bus_fds_truncated(void) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_close_ int memfd0 = -EBADF, memfd1 = -EBADF;
        _cleanup_free_ void *blob = NULL;
        _cleanup_free_ int *fds = NULL;
        ino_t ino0, ino1;
        size_t blob_size;
        int fd;

        /* Create two memfds and record their inodes for later verification */
        memfd0 = ASSERT_OK(memfd_create_wrapper("test-fd-0", /* mode= */ 0));
        ino0 = get_inode(memfd0);

        memfd1 = ASSERT_OK(memfd_create_wrapper("test-fd-1", /* mode= */ 0));
        ino1 = get_inode(memfd1);

        /* Create a bus for message operations (no actual connection needed) */
        ASSERT_OK(sd_bus_new(&bus));
        bus->state = BUS_RUNNING; /* Fake state to allow message creation */
        bus->can_fds = true;      /* Allow fd passing */

        /* Build a message containing two fds */
        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foo.bar", "/", "foo.bar", "Ping"));
        ASSERT_OK(sd_bus_message_append(m, "hh", memfd0, memfd1));
        ASSERT_OK(sd_bus_message_seal(m, 1, /* timeout_usec= */ 0));

        /* Serialize the message to a blob */
        ASSERT_OK(bus_message_get_blob(m, &blob, &blob_size));
        m = sd_bus_message_unref(m);

        /* Duplicate the fds since bus_message_from_malloc() takes ownership */
        fds = ASSERT_NOT_NULL(new(int, 2));
        fds[0] = ASSERT_OK_ERRNO(fcntl(memfd0, F_DUPFD_CLOEXEC, 3));
        fds[1] = ASSERT_OK_ERRNO(fcntl(memfd1, F_DUPFD_CLOEXEC, 3));

        /* Test 1: Parse with correct fd count, no truncation - should succeed */
        log_info("Test 1: Exact fd count match, got_ctrunc=false");
        void *blob_copy = ASSERT_NOT_NULL(memdup(blob, blob_size));
        ASSERT_OK(bus_message_from_malloc(bus, blob_copy, blob_size, fds, 2, /* got_ctrunc= */ false, /* label= */ NULL, &m));

        /* Verify we can read both fds and they have the expected inodes */
        ASSERT_OK(sd_bus_message_read_basic(m, 'h', &fd));
        ASSERT_EQ(get_inode(fd), ino0);
        ASSERT_OK(sd_bus_message_read_basic(m, 'h', &fd));
        ASSERT_EQ(get_inode(fd), ino1);

        m = sd_bus_message_unref(m);
        fds = NULL; /* ownership transferred */

        /* Test 2: Parse with fewer fds than declared, no truncation flag - should fail */
        log_info("Test 2: Fewer fds than declared, got_ctrunc=false");
        fds = ASSERT_NOT_NULL(new(int, 1));
        fds[0] = ASSERT_OK_ERRNO(fcntl(memfd0, F_DUPFD_CLOEXEC, 3));

        blob_copy = ASSERT_NOT_NULL(memdup(blob, blob_size));
        ASSERT_ERROR(bus_message_from_malloc(bus, blob_copy, blob_size, fds, 1, /* got_ctrunc= */ false, /* label= */ NULL, &m), EBADMSG);
        free(blob_copy);
        close(fds[0]);
        fds = mfree(fds);

        /* Test 3: Parse with fewer fds than declared, with truncation flag - parsing should succeed */
        log_info("Test 3: Fewer fds than declared, got_ctrunc=true");
        fds = ASSERT_NOT_NULL(new(int, 1));
        fds[0] = ASSERT_OK_ERRNO(fcntl(memfd0, F_DUPFD_CLOEXEC, 3));

        blob_copy = ASSERT_NOT_NULL(memdup(blob, blob_size));
        ASSERT_OK(bus_message_from_malloc(bus, blob_copy, blob_size, fds, 1, /* got_ctrunc= */ true, /* label= */ NULL, &m));

        /* First fd should be readable and have correct inode */
        ASSERT_OK(sd_bus_message_read_basic(m, 'h', &fd));
        ASSERT_EQ(get_inode(fd), ino0);

        /* Second fd was truncated - reading it should fail */
        ASSERT_ERROR(sd_bus_message_read_basic(m, 'h', &fd), EBADMSG);

        m = sd_bus_message_unref(m);
        fds = NULL; /* ownership transferred */

        /* Test 4: Parse with more fds than declared, with truncation flag - should fail */
        log_info("Test 4: More fds than declared, got_ctrunc=true");
        fds = ASSERT_NOT_NULL(new(int, 3));
        fds[0] = ASSERT_OK_ERRNO(fcntl(memfd0, F_DUPFD_CLOEXEC, 3));
        fds[1] = ASSERT_OK_ERRNO(fcntl(memfd1, F_DUPFD_CLOEXEC, 3));
        fds[2] = ASSERT_OK_ERRNO(fcntl(memfd0, F_DUPFD_CLOEXEC, 3));

        blob_copy = ASSERT_NOT_NULL(memdup(blob, blob_size));
        ASSERT_ERROR(bus_message_from_malloc(bus, blob_copy, blob_size, fds, 3, /* got_ctrunc= */ true, /* label= */ NULL, &m), EBADMSG);
        free(blob_copy);
        close(fds[0]);
        close(fds[1]);
        close(fds[2]);
        fds = mfree(fds);

        /* Test 5: Parse with zero fds when two were declared, with truncation flag - should succeed */
        log_info("Test 5: Zero fds when some declared, got_ctrunc=true");
        blob_copy = ASSERT_NOT_NULL(memdup(blob, blob_size));
        ASSERT_OK(bus_message_from_malloc(bus, blob_copy, blob_size, /* fds= */ NULL, /* n_fds= */ 0, /* got_ctrunc= */ true, /* label= */ NULL, &m));

        /* Both fd reads should fail since all were truncated */
        ASSERT_ERROR(sd_bus_message_read_basic(m, 'h', &fd), EBADMSG);

        m = sd_bus_message_unref(m);

        log_info("All fd truncation tests passed");
}

static void test_bus_nested_variant_depth_limit(void) {
        /* Craft a raw D-Bus message with an unknown header field whose value is a variant
         * containing a variant containing a variant... nested beyond BUS_CONTAINER_DEPTH.
         * Without the depth limit in message_skip_fields(), this causes unbounded recursion
         * and stack overflow. With the fix, it should be rejected with -EBADMSG. */

        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const unsigned depth = BUS_CONTAINER_DEPTH + 1; /* one past the limit */

        /* Each nesting level in the fields area is: 1 byte sig_len + 1 byte 'v' + 1 byte NUL = 3 bytes.
         * The innermost level has sig_len=1, 'u', NUL, then 4 bytes for the uint32 value.
         * The field header is: 1 byte field_code + 1 byte sig_len + 1 byte 'v' + 1 byte NUL = 4 bytes. */
        size_t fields_size = 4 + (depth * 3) + 4; /* field header + nested variant sigs + uint32 */
        size_t padded_fields = ALIGN8(fields_size);
        size_t total = sizeof(BusMessageHeader) + padded_fields;

        _cleanup_free_ void *buf = ASSERT_PTR(malloc0(total));

        BusMessageHeader *h = buf;
        *h = (BusMessageHeader) {
                .endian = BUS_NATIVE_ENDIAN,
                .type = SD_BUS_MESSAGE_METHOD_CALL,
                .version = 1,
                .serial = 1,
                .fields_size = (uint32_t) fields_size,
        };

        uint8_t *p = (uint8_t *) buf + sizeof(BusMessageHeader);

        /* Unknown field code (triggers default: in message_parse_fields) */
        *p++ = 0xFF;
        /* Field signature: variant */
        *p++ = 1;    /* sig length */
        *p++ = 'v';
        *p++ = '\0';

        /* Nested variant signatures: each level declares its content is another variant */
        for (unsigned i = 0; i < depth; i++) {
                *p++ = 1;    /* sig length */
                *p++ = 'v';
                *p++ = '\0';
        }

        /* Innermost value: a uint32 */
        memset(p, 0, 4);

        ASSERT_OK(sd_bus_new(&bus));

        ASSERT_ERROR(bus_message_from_malloc(bus, buf, total, /* fds= */ NULL, /* n_fds= */ 0, /* got_ctrunc= */ false, /* label= */ NULL, &m), EBADMSG);
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

        ASSERT_OK(sd_bus_message_new_method_call(bus, &m, "foobar.waldo", "/", "foobar.waldo", "Piep"));

        ASSERT_OK(sd_bus_message_append(m, ""));

        ASSERT_OK(sd_bus_message_append(m, "s", "a string"));

        ASSERT_OK(sd_bus_message_append(m, "s", NULL));

        ASSERT_OK(sd_bus_message_append(m, "asg", 2, "string #1", "string #2", "sba(tt)ss"));

        ASSERT_OK(sd_bus_message_append(m, "sass", "foobar",
                                        5, "foo", "bar", "waldo", "piep", "pap",
                                        "after"));

        ASSERT_OK(sd_bus_message_append(m, "a{yv}", 2, 3, "s", "foo", 5, "s", "waldo"));

        ASSERT_OK(sd_bus_message_append(m, "y(ty)y(yt)y", 8, 777ULL, 7, 9, 77, 7777ULL, 10));

        ASSERT_ERROR(sd_bus_message_append(m, "()"), EINVAL);

        ASSERT_OK(sd_bus_message_append(m, "ba(ss)", 255, 3, "aaa", "1", "bbb", "2", "ccc", "3"));

        ASSERT_OK(sd_bus_message_open_container(m, 'a', "s"));

        ASSERT_OK(sd_bus_message_append_basic(m, 's', "foobar"));

        ASSERT_OK(sd_bus_message_append_basic(m, 's', "waldo"));

        ASSERT_OK(sd_bus_message_close_container(m));

        ASSERT_OK(sd_bus_message_append_string_space(m, 5, &s));
        strcpy(s, "hallo");

        ASSERT_OK(sd_bus_message_append_array(m, 'i', integer_array, sizeof(integer_array)));

        ASSERT_OK(sd_bus_message_append_array(m, 'u', /* ptr= */ NULL, /* size= */ 0));

        ASSERT_OK(sd_bus_message_append(m, "a(stdo)", 1, "foo", 815ULL, 47.0, "/"));

        ASSERT_OK(sd_bus_message_seal(m, 4711, /* timeout_usec= */ 0));

        sd_bus_message_dump(m, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        ASSERT_NOT_NULL(mf = memstream_init(&ms));
        sd_bus_message_dump(m, mf, /* flags= */ 0);
        ASSERT_OK(memstream_finalize(&ms, &first, &first_size));

        ASSERT_OK(bus_message_get_blob(m, &buffer, &sz));

        h = ASSERT_NOT_NULL(cescape_length(buffer, sz));
        log_info("message size = %zu, contents =\n%s", sz, h);

#if HAVE_GLIB
        if (dlopen_glib() >= 0) {
                GDBusMessage *g;
                char *p;

                g = sym_g_dbus_message_new_from_blob(buffer, sz, /* capabilities= */ 0, /* error= */ NULL);
                p = sym_g_dbus_message_print(g, /* indent= */ 0);
                log_info("%s", p);
                sym_g_free(p);
                sym_g_object_unref(g);
        }
#endif

#if HAVE_DBUS
        if (dlopen_libdbus() >= 0) {
                DBusMessage *w;
                DBusError error;

                sym_dbus_error_init(&error);

                w = sym_dbus_message_demarshal(buffer, sz, &error);
                if (!w)
                        log_error("%s", error.message);
                else
                        sym_dbus_message_unref(w);

                sym_dbus_error_free(&error);
        }
#endif

        m = sd_bus_message_unref(m);

        ASSERT_OK(bus_message_from_malloc(bus, buffer, sz, /* fds= */ NULL, /* n_fds= */ 0, /* got_ctrunc= */ false, /* label= */ NULL, &m));

        sd_bus_message_dump(m, stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        ASSERT_NOT_NULL(mf = memstream_init(&ms));
        sd_bus_message_dump(m, mf, /* flags= */ 0);
        ASSERT_OK(memstream_finalize(&ms, &second, &second_size));
        ASSERT_EQ(first_size, second_size);
        ASSERT_EQ(memcmp(first, second, first_size), 0);

        ASSERT_OK(sd_bus_message_rewind(m, /* complete= */ true));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "ssasg", &x, &x2, 2, &y, &z, &a_signature));
        ASSERT_STREQ(x, "a string");
        ASSERT_STREQ(x2, "");
        ASSERT_STREQ(y, "string #1");
        ASSERT_STREQ(z, "string #2");
        ASSERT_STREQ(a_signature, "sba(tt)ss");

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "sass", &x, 5, &y, &z, &a, &b, &c, &d));
        ASSERT_STREQ(x, "foobar");
        ASSERT_STREQ(y, "foo");
        ASSERT_STREQ(z, "bar");
        ASSERT_STREQ(a, "waldo");
        ASSERT_STREQ(b, "piep");
        ASSERT_STREQ(c, "pap");
        ASSERT_STREQ(d, "after");

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "a{yv}", 2, &u, "s", &x, &v, "s", &y));
        ASSERT_EQ(u, 3U);
        ASSERT_STREQ(x, "foo");
        ASSERT_EQ(v, 5);
        ASSERT_STREQ(y, "waldo");

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "y(ty)", &v, &u64, &u));
        ASSERT_EQ(v, 8);
        ASSERT_EQ(u64, 777U);
        ASSERT_EQ(u, 7U);

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "y(yt)", &v, &u, &u64));
        ASSERT_EQ(v, 9);
        ASSERT_EQ(u, 77U);
        ASSERT_EQ(u64, 7777U);

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "y", &v));
        ASSERT_EQ(v, 10);

        ASSERT_FAIL(sd_bus_message_read(m, "()"));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "ba(ss)", &boolean, 3, &x, &y, &a, &b, &c, &d));
        ASSERT_TRUE(boolean);
        ASSERT_STREQ(x, "aaa");
        ASSERT_STREQ(y, "1");
        ASSERT_STREQ(a, "bbb");
        ASSERT_STREQ(b, "2");
        ASSERT_STREQ(c, "ccc");
        ASSERT_STREQ(d, "3");

        ASSERT_OK_POSITIVE(sd_bus_message_verify_type(m, 'a', "s"));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "as", 2, &x, &y));
        ASSERT_STREQ(x, "foobar");
        ASSERT_STREQ(y, "waldo");

        ASSERT_OK_POSITIVE(sd_bus_message_read_basic(m, 's', &s));
        ASSERT_STREQ(s, "hallo");

        ASSERT_OK_POSITIVE(sd_bus_message_read_array(m, 'i', (const void**) &return_array, &sz));
        ASSERT_EQ(sz, sizeof(integer_array));
        ASSERT_EQ(memcmp(integer_array, return_array, sz), 0);

        ASSERT_OK_POSITIVE(sd_bus_message_read_array(m, 'u', (const void**) &return_array, &sz));
        ASSERT_EQ(sz, 0U);

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "a(stdo)", 1, &x, &u64, &dbl, &y));
        ASSERT_STREQ(x, "foo");
        ASSERT_EQ(u64, 815ULL);
        ASSERT_TRUE(ABS(dbl - 47.0) < 0.1);
        ASSERT_STREQ(y, "/");

        ASSERT_OK_ZERO(sd_bus_message_peek_type(m, /* ret_type= */ NULL, /* ret_contents= */ NULL));

        ASSERT_OK(sd_bus_message_new_method_call(bus, &copy, "foobar.waldo", "/", "foobar.waldo", "Piep"));

        ASSERT_OK(sd_bus_message_rewind(m, /* complete= */ true));

        ASSERT_OK(sd_bus_message_copy(copy, m, /* all= */ true));

        ASSERT_OK(sd_bus_message_seal(copy, 4712, /* timeout_usec= */ 0));

        ASSERT_NOT_NULL(mf = memstream_init(&ms));
        sd_bus_message_dump(copy, mf, /* flags= */ 0);
        ASSERT_OK(memstream_finalize(&ms, &third, &third_size));

        printf("<%.*s>\n", (int) first_size, first);
        printf("<%.*s>\n", (int) third_size, third);

        ASSERT_EQ(first_size, third_size);
        ASSERT_EQ(memcmp(first, third, third_size), 0);

        ASSERT_OK(sd_bus_message_rewind(m, /* complete= */ true));

        ASSERT_OK_POSITIVE(sd_bus_message_verify_type(m, 's', /* contents= */ NULL));

        ASSERT_OK_POSITIVE(sd_bus_message_skip(m, "ssasg"));

        ASSERT_OK_POSITIVE(sd_bus_message_verify_type(m, 's', /* contents= */ NULL));

        ASSERT_OK(sd_bus_message_skip(m, "sass"));

        ASSERT_OK_POSITIVE(sd_bus_message_verify_type(m, 'a', "{yv}"));

        ASSERT_OK(sd_bus_message_skip(m, "a{yv}y(ty)y(yt)y"));

        ASSERT_OK_POSITIVE(sd_bus_message_verify_type(m, 'b', /* contents= */ NULL));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "b", &boolean));
        ASSERT_TRUE(boolean);

        ASSERT_OK_POSITIVE(sd_bus_message_enter_container(m, /* type= */ 0, /* contents= */ NULL));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "(ss)", &x, &y));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "(ss)", &a, &b));

        ASSERT_OK_POSITIVE(sd_bus_message_read(m, "(ss)", &c, &d));

        ASSERT_OK_ZERO(sd_bus_message_read(m, "(ss)", &x, &y));

        ASSERT_OK(sd_bus_message_exit_container(m));

        ASSERT_STREQ(x, "aaa");
        ASSERT_STREQ(y, "1");
        ASSERT_STREQ(a, "bbb");
        ASSERT_STREQ(b, "2");
        ASSERT_STREQ(c, "ccc");
        ASSERT_STREQ(d, "3");

        test_bus_label_escape();
        test_bus_path_encode();
        test_bus_path_encode_unique();
        test_bus_path_encode_many();
        test_bus_fds_truncated();
        test_bus_nested_variant_depth_limit();

        return 0;
}
