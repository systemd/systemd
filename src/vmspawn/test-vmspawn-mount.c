/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "vmspawn-mount.h"

TEST(runtime_mount_parse) {
        _cleanup_(runtime_mount_context_done) RuntimeMountContext ctx = {};

        ASSERT_OK(runtime_mount_parse(&ctx, "/:/run/x", /* read_only= */ false));
        ASSERT_EQ(ctx.n_mounts, 1u);
        ASSERT_STREQ(ctx.mounts[0].source, "/");
        ASSERT_STREQ(ctx.mounts[0].target, "/run/x");
        ASSERT_FALSE(ctx.mounts[0].read_only);

        ASSERT_OK(runtime_mount_parse(&ctx, "/usr", /* read_only= */ true));
        ASSERT_EQ(ctx.n_mounts, 2u);
        ASSERT_STREQ(ctx.mounts[1].source, "/usr");
        ASSERT_STREQ(ctx.mounts[1].target, "/usr");
        ASSERT_TRUE(ctx.mounts[1].read_only);

        ASSERT_ERROR(runtime_mount_parse(&ctx, "/:run/x", /* read_only= */ false), EINVAL);
        ASSERT_ERROR(runtime_mount_parse(&ctx, "/:/run/x/../../srv", /* read_only= */ false), EINVAL);
        ASSERT_ERROR(runtime_mount_parse(&ctx, "/:/run/x/..", /* read_only= */ false), EINVAL);
        ASSERT_ERROR(runtime_mount_parse(&ctx, "/:/../srv", /* read_only= */ false), EINVAL);
        ASSERT_ERROR(runtime_mount_parse(&ctx, "/usr/../usr", /* read_only= */ false), EINVAL);
        ASSERT_EQ(ctx.n_mounts, 2u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
