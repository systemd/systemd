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

DEFINE_TEST_MAIN(LOG_INFO);
