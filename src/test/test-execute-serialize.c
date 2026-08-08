/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "cgroup.h"
#include "dynamic-user.h"
#include "execute-serialize.h"
#include "execute.h"
#include "fd-util.h"
#include "fdset.h"
#include "fs-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void copy_file(FILE *dest, FILE *source) {
        uint8_t buf[4096];

        while (true) {
                size_t read = fread(buf, sizeof(*buf), ELEMENTSOF(buf), source);

                if (read < 1)
                        break;

                assert_se(fwrite(buf, sizeof(*buf), read, dest) == read);
        }
}

typedef struct RoundtripState {
        ExecContext *exec_context;
} RoundtripState;

typedef void(RoundtripHook)(RoundtripState *);

static void test_roundtrip_by_calling(RoundtripHook *setup, RoundtripHook *check) {
        /* set up the buffer */

        _cleanup_fclose_ FILE *buffer = NULL;
        _cleanup_(unlink_and_freep) char *tmpfile = NULL;
        const char *filename = "buffer.txt";
        int r = fopen_tmpfile_linkable(filename, O_RDWR | O_CLOEXEC, &tmpfile, &buffer);

        if (r < 0)
                log_test_failed("Failed to create '%s': %m", filename);

        /* set up the dummy params */

        _cleanup_fdset_free_ FDSet *fds = ASSERT_SE_PTR(fdset_new());
        _cleanup_(exec_params_deep_clear) ExecParameters params = EXEC_PARAMETERS_INIT(/* flags= */ 0);
        _cleanup_(exec_context_done) ExecContext exec_context = {};
        _cleanup_(cgroup_context_done) CGroupContext cgroup_context = {};
        DynamicCreds dynamic_creds = {};
        ExecCommand command = {};
        ExecSharedRuntime shared = {
                .userns_storage_socket = EBADF_PAIR,
                .netns_storage_socket = EBADF_PAIR,
                .ipcns_storage_socket = EBADF_PAIR,
        };
        ExecRuntime runtime = {
                .ephemeral_storage_socket = EBADF_PAIR,
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };

        /* set up the test data */

        RoundtripState state = { .exec_context = &exec_context };

        if (setup)
                setup(&state);

        assert_se(exec_serialize_invocation(buffer, fds, &exec_context,
                &command, NULL, NULL, NULL) >= 0);

        exec_context_done(&exec_context);

        rewind(buffer);
        copy_file(stdout, buffer);

        rewind(buffer);
        assert_se(exec_deserialize_invocation(buffer, fds, &exec_context,
                &command, &params, &runtime, &cgroup_context) >= 0);

        if (check)
                check(&state);
}

/* Test whether BindPaths=, BindReadOnlyPaths=, MountImage=, and ExtensionImage= paths containing quote
   characters survive a roundtrip. */

static const char *quotes_strs[] = {
        "'text here'", "'text here",  "text 'here",    "text' 'here", "text here'", "\"text here\"",
        "\"text here", "text \"here", "text\" \"here", "text here\"", "'\"'\"'\"",
};

static void roundtrip_quotes_setup(RoundtripState *s) {
        FOREACH_ELEMENT(str, quotes_strs) {
                assert_se(bind_mount_add(&s->exec_context->bind_mounts, &s->exec_context->n_bind_mounts, &(BindMount) {
                        .source = (char *) *str,
                        .destination = (char *) *str,
                        .read_only = false,
                        0,
                }) >= 0);

                assert_se(bind_mount_add(&s->exec_context->bind_mounts, &s->exec_context->n_bind_mounts, &(BindMount) {
                        .source = (char *) *str,
                        .destination = (char *) *str,
                        .read_only = true,
                        0,
                }) >= 0);

                assert_se(mount_image_add(&s->exec_context->mount_images, &s->exec_context->n_mount_images, &(MountImage) {
                        .source = (char *) *str,
                        .destination = (char *) *str,
                        0,
                }) >= 0);

                assert_se(mount_image_add(&s->exec_context->extension_images, &s->exec_context->n_extension_images, &(MountImage) {
                        .source = (char *) *str,
                        0,
                }) >= 0);
        }
}

static void roundtrip_quotes_check(RoundtripState *s) {
        assert_se(s->exec_context->n_bind_mounts == 2 * ELEMENTSOF(quotes_strs));
        assert_se(s->exec_context->n_mount_images == ELEMENTSOF(quotes_strs));
        assert_se(s->exec_context->n_extension_images == ELEMENTSOF(quotes_strs));

        for (size_t pos = 0; pos < ELEMENTSOF(quotes_strs); pos++) {
                size_t bind_mount_base = 2 * pos;

                const char *expected = quotes_strs[pos];

                assert_se(!s->exec_context->bind_mounts[bind_mount_base].read_only);
                assert_se(streq(expected, s->exec_context->bind_mounts[bind_mount_base].source));
                assert_se(streq(expected, s->exec_context->bind_mounts[bind_mount_base].destination));

                assert_se(s->exec_context->bind_mounts[bind_mount_base + 1].read_only);
                assert_se(streq(expected, s->exec_context->bind_mounts[bind_mount_base + 1].source));
                assert_se(streq(expected, s->exec_context->bind_mounts[bind_mount_base + 1].destination));

                assert_se(streq(expected, s->exec_context->mount_images[pos].source));
                assert_se(streq(expected, s->exec_context->mount_images[pos].destination));

                assert_se(streq(expected, s->exec_context->extension_images[pos].source));
        }
}

TEST(roundtrip_quotes) {
        test_roundtrip_by_calling(roundtrip_quotes_setup, roundtrip_quotes_check);
}

/* Test whether MountImage= and ExtensionImage= paths containing (trailing) space characters survive a roundtrip. */

static const char *spaces_str = "  I contain leading and trailing spaces  ";

static void roundtrip_spaces_setup(RoundtripState *s) {
        assert_se(mount_image_add(&s->exec_context->mount_images, &s->exec_context->n_mount_images, &(MountImage) {
                .source = (char *) spaces_str,
                .destination = (char *) spaces_str,
                0,
        }) >= 0);

        assert_se(mount_image_add(&s->exec_context->extension_images, &s->exec_context->n_extension_images, &(MountImage) {
                .source = (char *) spaces_str,
                0,
        }) >= 0);
}

static void roundtrip_spaces_check(RoundtripState *s) {
        assert_se(s->exec_context->n_mount_images == 1);
        assert_se(s->exec_context->n_extension_images == 1);

        assert_se(streq(spaces_str, s->exec_context->mount_images[0].source));
        assert_se(streq(spaces_str, s->exec_context->mount_images[0].destination));

        assert_se(streq(spaces_str, s->exec_context->extension_images[0].source));
}

TEST(roundtrip_spaces) {
        test_roundtrip_by_calling(roundtrip_spaces_setup, roundtrip_spaces_check);
}

DEFINE_TEST_MAIN(LOG_INFO);
