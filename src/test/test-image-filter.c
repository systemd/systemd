/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dissect-image.h"
#include "tests.h"

TEST(image_filter) {
        _cleanup_(image_filter_freep) ImageFilter *f = NULL;

        ASSERT_OK(image_filter_parse(NULL, &f));
        ASSERT_NULL(f);
        ASSERT_OK(image_filter_parse("", &f));
        ASSERT_NULL(f);

        ASSERT_OK(image_filter_parse("root=*", &f));
        ASSERT_NOT_NULL(f);
        ASSERT_STREQ(f->pattern[PARTITION_ROOT], "*");
        f = image_filter_free(f);

        ASSERT_OK(image_filter_parse("usr=foox?:root=kn*arz", &f));
        ASSERT_NOT_NULL(f);
        ASSERT_STREQ(f->pattern[PARTITION_ROOT], "kn*arz");
        ASSERT_STREQ(f->pattern[PARTITION_USR], "foox?");
        f = image_filter_free(f);

        ASSERT_OK(image_filter_parse("usr=foox?:root=kn*arz:home=wumpi", &f));
        ASSERT_NOT_NULL(f);
        ASSERT_STREQ(f->pattern[PARTITION_ROOT], "kn*arz");
        ASSERT_STREQ(f->pattern[PARTITION_USR], "foox?");
        ASSERT_STREQ(f->pattern[PARTITION_HOME], "wumpi");
        f = image_filter_free(f);

        ASSERT_ERROR(image_filter_parse("usr=foox?:root=kn*arz:home=wumpi:schlumpf=smurf", &f), EINVAL);
        ASSERT_ERROR(image_filter_parse(":", &f), EINVAL);
        ASSERT_ERROR(image_filter_parse("::", &f), EINVAL);
        ASSERT_ERROR(image_filter_parse("-", &f), EINVAL);
        ASSERT_ERROR(image_filter_parse("root=knuff:root=knuff", &f), EINVAL);
}

TEST(image_filter_test_basic) {
        _cleanup_(image_filter_freep) ImageFilter *f = NULL;

        /* NULL filter matches everything */
        ASSERT_TRUE(image_filter_test(NULL, PARTITION_ROOT, "foo"));
        ASSERT_TRUE(image_filter_test(NULL, PARTITION_USR, "bar"));
        ASSERT_TRUE(image_filter_test(NULL, PARTITION_USR_VERITY, "baz"));

        /* Filter on usr matches the right label */
        ASSERT_OK(image_filter_parse("usr=250", &f));
        ASSERT_TRUE(image_filter_test(f, PARTITION_USR, "250"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_USR, "251"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_USR, ""));

        /* Unfiltered designators pass through */
        ASSERT_TRUE(image_filter_test(f, PARTITION_ROOT, "anything"));
        ASSERT_TRUE(image_filter_test(f, PARTITION_HOME, "anything"));
}

TEST(image_filter_test_verity_fallback) {
        _cleanup_(image_filter_freep) ImageFilter *f = NULL;

        /* Filter on usr= should also constrain usr-verity and usr-verity-sig */
        ASSERT_OK(image_filter_parse("usr=250", &f));
        ASSERT_TRUE(image_filter_test(f, PARTITION_USR_VERITY, "250"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_USR_VERITY, "251"));
        ASSERT_TRUE(image_filter_test(f, PARTITION_USR_VERITY_SIG, "250"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_USR_VERITY_SIG, "251"));

        f = image_filter_free(f);

        /* Filter on root= should also constrain root-verity and root-verity-sig */
        ASSERT_OK(image_filter_parse("root=A", &f));
        ASSERT_TRUE(image_filter_test(f, PARTITION_ROOT_VERITY, "A"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_ROOT_VERITY, "B"));
        ASSERT_TRUE(image_filter_test(f, PARTITION_ROOT_VERITY_SIG, "A"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_ROOT_VERITY_SIG, "B"));

        /* Unrelated verity-less designators are not affected */
        ASSERT_TRUE(image_filter_test(f, PARTITION_HOME, "anything"));

        f = image_filter_free(f);

        /* Glob patterns should work through the fallback too */
        ASSERT_OK(image_filter_parse("usr=25*", &f));
        ASSERT_TRUE(image_filter_test(f, PARTITION_USR_VERITY, "250"));
        ASSERT_TRUE(image_filter_test(f, PARTITION_USR_VERITY, "259"));
        ASSERT_FALSE(image_filter_test(f, PARTITION_USR_VERITY, "260"));
}

DEFINE_TEST_MAIN(LOG_INFO);
