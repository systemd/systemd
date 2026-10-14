/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup.h"
#include "dynamic-user.h"
#include "execute-serialize.h"
#include "execute.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "strv.h"
#include "tests.h"

static const char* const paths[] = {
        "plain", "with space", "with'quote", "with\"quote", "with:colon",
        "with\\backslash", "with\ttab", "with\nnewline", "with%specifier", "private-other",
};

static void assert_directory(
                const ExecDirectory *d,
                const char *source,
                const char *destination,
                ExecDirectoryFlags flags) {
        ASSERT_EQ(d->n_items, 1U);
        ASSERT_STREQ(d->items[0].path, source);
        ASSERT_EQ(d->items[0].flags, flags);
        if (isempty(destination))
                ASSERT_TRUE(strv_isempty(d->items[0].symlinks));
        else {
                ASSERT_EQ(strv_length(d->items[0].symlinks), 1U);
                ASSERT_STREQ(d->items[0].symlinks[0], destination);
        }
}

TEST(executor_directory_roundtrip) {
        FOREACH_ELEMENT(path, paths) {
                _cleanup_(exec_context_done) ExecContext context = {}, parsed = {};
                _cleanup_(exec_params_deep_clear) ExecParameters parameters = EXEC_PARAMETERS_INIT(0);
                _cleanup_(cgroup_context_done) CGroupContext cgroup = {};
                _cleanup_(exec_command_done) ExecCommand command = {};
                _cleanup_fdset_free_ FDSet *fds = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_(exec_shared_runtime_done) ExecSharedRuntime shared = {
                        .userns_storage_socket = EBADF_PAIR,
                        .netns_storage_socket = EBADF_PAIR,
                        .ipcns_storage_socket = EBADF_PAIR,
                };
                _cleanup_(dynamic_creds_done) DynamicCreds creds = {};
                _cleanup_(exec_runtime_clear) ExecRuntime runtime = {
                        .ephemeral_storage_socket = EBADF_PAIR,
                        .shared = &shared,
                        .dynamic_creds = &creds,
                };

                exec_context_init(&context);
                exec_context_init(&parsed);
                context.private_var_tmp = PRIVATE_TMP_DISCONNECTED;
                sd_id128_to_string(parameters.invocation_id, parameters.invocation_id_string);
                cgroup_context_init(&cgroup);
                ASSERT_NOT_NULL(fds = fdset_new());
                ASSERT_NOT_NULL(f = tmpfile());

                for (ExecDirectoryType type = 0; type < _EXEC_DIRECTORY_TYPE_MAX; type++)
                        ASSERT_OK(exec_directory_add(&context.directories[type], *path,
                                                     type == EXEC_DIRECTORY_CONFIGURATION ? NULL : *path,
                                                     EXEC_DIRECTORY_READ_ONLY));

                ASSERT_OK(exec_serialize_invocation(f, fds, &context, &command, &parameters, NULL, &cgroup));
                ASSERT_OK_ERRNO(fseek(f, 0, SEEK_SET));
                ASSERT_OK(exec_deserialize_invocation(f, fds, &parsed, &command, &parameters, &runtime, &cgroup));

                for (ExecDirectoryType type = 0; type < _EXEC_DIRECTORY_TYPE_MAX; type++)
                        assert_directory(&parsed.directories[type], *path,
                                         type == EXEC_DIRECTORY_CONFIGURATION ? NULL : *path,
                                         EXEC_DIRECTORY_READ_ONLY);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
