/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "errno-util.h"
#include "extension-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "host-properties.h"
#include "path-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "xattr-util.h"

#define TEST_MACHINE_ID SD_ID128_MAKE(4b,1f,7c,95,0d,4f,4e,1a,9e,8f,3d,22,57,61,80,a3)

static void host_init(HostProperties *h) {
        *h = HOST_PROPERTIES_NULL;
        ASSERT_NOT_NULL(h->hostname = strdup("foo.example.com"));
        h->machine_id = TEST_MACHINE_ID;
        ASSERT_NOT_NULL(h->machine_tags = strv_new("rack=7", "server"));
        ASSERT_NOT_NULL(h->os_id = strdup("fedora"));
        ASSERT_NOT_NULL(h->os_version_id = strdup("44"));
        ASSERT_NOT_NULL(h->image_id = strdup("appliance"));
        ASSERT_NOT_NULL(h->image_version = strdup("1.2.3"));
        h->loaded = true;
}

#define test_one(path, h, ...) \
        extension_match_host("test", path, STRV_MAKE("ID", "_any" __VA_OPT__(,) __VA_ARGS__), h, /* root= */ NULL)

TEST(extension_match_host) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_(host_properties_done) HostProperties h;
        int r;

        host_init(&h);

        ASSERT_OK(tfd = mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &t));
        ASSERT_OK(write_string_file_at(tfd, "ext.raw", "x", WRITE_STRING_FILE_CREATE));
        _cleanup_free_ char *p = ASSERT_NOT_NULL(path_join(t, "ext.raw"));

        /* No rules at all */
        ASSERT_OK_POSITIVE(test_one(p, &h));

        /* Rules in the extension-release file only: whitespace separated globs, any must match */
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_HOSTNAME", "foo.example.com"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_HOSTNAME", "bar  foo.*"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_HOSTNAME", "bar foo"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_HOSTNAME", ""));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_MACHINE_ID", "00000000000000000000000000000000 4b1f*"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_MACHINE_ID", "00000000000000000000000000000000"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_MACHINE_TAGS", "web rack=*"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_MACHINE_TAGS", "web"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_HOSTNAME", "foo*", "MATCH_MACHINE_TAGS", "web"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_HOSTNAME", "\xff"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_OS_ID", "debian fed*"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_OS_ID", "debian"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_OS_VERSION_ID", ">=40 <50"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_OS_VERSION_ID", ">=40 <42"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_OS_VERSION_ID", ">="));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_IMAGE_ID", "app*"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_IMAGE_ID", "other"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_IMAGE_VERSION", "=1.2.3"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_IMAGE_VERSION", ">1.2.3"));

        r = xsetxattr_strv(tfd, "ext.raw", /* at_flags= */ 0, "user.uapi.match_hostname", STRV_MAKE("bar", "foo.*"));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "File system does not support user extended attributes");
        ASSERT_OK(r);

        /* Rules in the extended attributes only */
        ASSERT_OK_POSITIVE(test_one(p, &h));

        /* Rules for different properties in both are combined */
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_MACHINE_TAGS", "server"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_MACHINE_TAGS", "web"));

        /* The same rules for the same property in both, in different order */
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_HOSTNAME", "foo.* bar"));

        /* Contradicting rules for the same property: both are honoured (and a warning is logged) */
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_HOSTNAME", "bar"));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_HOSTNAME", "*.example.com"));

        ASSERT_OK(xsetxattr_strv(tfd, "ext.raw", /* at_flags= */ 0, "user.uapi.match_hostname", STRV_MAKE("bar")));
        ASSERT_OK_ZERO(test_one(p, &h));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_HOSTNAME", "foo.*"));

        /* Extended attributes for other properties are honoured too */
        ASSERT_OK(xsetxattr_strv(tfd, "ext.raw", /* at_flags= */ 0, "user.uapi.match_hostname", STRV_MAKE("foo.*")));
        ASSERT_OK(xsetxattr_strv(tfd, "ext.raw", /* at_flags= */ 0, "user.uapi.match_os_id", STRV_MAKE("debian")));
        ASSERT_OK_ZERO(test_one(p, &h));
        ASSERT_OK(xsetxattr_strv(tfd, "ext.raw", /* at_flags= */ 0, "user.uapi.match_os_id", STRV_MAKE("fedora")));
        ASSERT_OK_POSITIVE(test_one(p, &h));

        /* Extended attribute and field for a version property: both are honoured */
        ASSERT_OK(xsetxattr_strv(tfd, "ext.raw", /* at_flags= */ 0, "user.uapi.match_os_version_id", STRV_MAKE(">= 40")));
        ASSERT_OK_POSITIVE(test_one(p, &h));
        ASSERT_OK_POSITIVE(test_one(p, &h, "MATCH_OS_VERSION_ID", ">=40"));
        ASSERT_OK_ZERO(test_one(p, &h, "MATCH_OS_VERSION_ID", "<44"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
