/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "initrd-cpio.h"
#include "machine-credential.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST_RET(initrd_cpio_credentials_basic) {
        struct stat st;
        size_t foo_size, bar_size;
        _cleanup_free_ char *cmd = NULL, *extra_path = NULL, *creds_path = NULL, *foo_path = NULL, *bar_path = NULL, *foo_content = NULL, *bar_content = NULL;
        _cleanup_(machine_credential_context_done) MachineCredentialContext creds = {};
        _cleanup_(unlink_and_freep) char *cpio_path = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *extract_dir = NULL;
        int r;

        r = find_executable("cpio", NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "Could not find cpio binary: %m");

        ASSERT_OK(machine_credential_add(&creds, "foo", "hello", 5));
        ASSERT_OK(machine_credential_add(&creds, "bar", "abc\0def", 7));

        ASSERT_OK(initrd_cpio_credentials_to_tempfile(&creds, &cpio_path));
        ASSERT_NOT_NULL(cpio_path);

        ASSERT_OK(mkdtemp_malloc(NULL, &extract_dir));
        ASSERT_OK(asprintf(&cmd, "cd %s && cpio -idm < %s", extract_dir, cpio_path));
        ASSERT_TRUE(system(cmd) == 0);

        ASSERT_NOT_NULL(extra_path = path_join(extract_dir, ".extra"));
        ASSERT_OK_ERRNO(stat(extra_path, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ((mode_t)(st.st_mode & 07777), (mode_t)0555);

        ASSERT_NOT_NULL(creds_path = path_join(extract_dir, ".extra/system_credentials"));
        ASSERT_OK_ERRNO(stat(creds_path, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ((mode_t)(st.st_mode & 07777), (mode_t)0500);

        ASSERT_NOT_NULL(foo_path = path_join(extract_dir, ".extra/system_credentials/foo.cred"));
        ASSERT_OK_ERRNO(stat(foo_path, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ((mode_t)(st.st_mode & 07777), (mode_t)0400);
        ASSERT_OK(read_full_file(foo_path, &foo_content, &foo_size));
        ASSERT_EQ(foo_size, 5U);
        ASSERT_TRUE(memcmp(foo_content, "hello", 5) == 0);

        ASSERT_NOT_NULL(bar_path = path_join(extract_dir, ".extra/system_credentials/bar.cred"));
        ASSERT_OK_ERRNO(stat(bar_path, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ((mode_t)(st.st_mode & 07777), (mode_t)0400);
        ASSERT_OK(read_full_file(bar_path, &bar_content, &bar_size));
        ASSERT_EQ(bar_size, 7U);
        ASSERT_TRUE(memcmp(bar_content, "abc\0def", 7) == 0);

        return 0;
}

TEST(initrd_cpio_credentials_rejects_invalid_name) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext creds = {};
        _cleanup_(unlink_and_freep) char *cpio_path = NULL;

        /* Bypass the validating machine_credential_add()/_set()/_load() helpers and inject an id that would
         * escape the .extra/system_credentials/ directory, to exercise the writer's defense-in-depth check. */
        ASSERT_NOT_NULL(creds.credentials = new0(MachineCredential, 1));
        creds.n_credentials = 1;
        ASSERT_NOT_NULL(creds.credentials[0].id = strdup("../../etc/evil"));
        ASSERT_NOT_NULL(creds.credentials[0].data = memdup("x", 1));
        creds.credentials[0].size = 1;

        ASSERT_ERROR(initrd_cpio_credentials_to_tempfile(&creds, &cpio_path), EINVAL);
        ASSERT_NULL(cpio_path);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
