/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "strv.h"
#include "sysupdate-component.h"
#include "sysupdate-update-set-flags.h"
#include "sysupdate-util.h"
#include "tests.h"

TEST(component_name_valid) {
        /* Valid component names: anything that turns "sysupdate.<name>.d" into a valid filename. */
        ASSERT_TRUE(component_name_valid("foo"));
        ASSERT_TRUE(component_name_valid("foo-bar"));
        ASSERT_TRUE(component_name_valid("foo.bar"));
        ASSERT_TRUE(component_name_valid("foo_bar_baz"));
        ASSERT_TRUE(component_name_valid("0815"));
        ASSERT_TRUE(component_name_valid("über"));            /* valid UTF-8 is fine */

        /* Invalid: empty, slashes, control characters, invalid UTF-8. */
        ASSERT_FALSE(component_name_valid(""));
        ASSERT_FALSE(component_name_valid("foo/bar"));
        ASSERT_FALSE(component_name_valid("/foo"));
        ASSERT_FALSE(component_name_valid("foo/"));
        ASSERT_FALSE(component_name_valid("foo\tbar"));
        ASSERT_FALSE(component_name_valid("foo\nbar"));
        ASSERT_FALSE(component_name_valid("foo\x7f"));
        ASSERT_FALSE(component_name_valid("\xff"));           /* not valid UTF-8 */
}

TEST(component_json) {
        _cleanup_(component_done) Component c = COMPONENT_NULL;

        ASSERT_NOT_NULL(c.description = strdup("Some component"));
        ASSERT_NOT_NULL(c.documentation = strv_new("https://example.com/doc", "https://example.com/more"));
        c.enabled = false;
        c.suggest = true;
        ASSERT_NOT_NULL(c.min_version = strdup("v1"));
        ASSERT_NOT_NULL(c.max_version = strdup("v9"));
        ASSERT_NOT_NULL(c.protected_versions = strv_new("v2", "v3"));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ASSERT_OK(component_to_json(&c, &v));

        _cleanup_(component_done) Component d = COMPONENT_NULL;
        ASSERT_OK(component_from_json(&d, v, "test"));
        ASSERT_STREQ(d.description, "Some component");
        ASSERT_TRUE(strv_equal(d.documentation, c.documentation));
        ASSERT_EQ(d.enabled, 0);
        ASSERT_EQ(d.suggest, 1);
        ASSERT_STREQ(d.min_version, "v1");
        ASSERT_STREQ(d.max_version, "v9");
        ASSERT_TRUE(strv_equal(d.protected_versions, c.protected_versions));

        /* Defaults apply for everything left out, or if there is no object at all */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        ASSERT_OK(sd_json_buildo(&w, SD_JSON_BUILD_PAIR_STRING("description", "Bare")));
        _cleanup_(component_done) Component e = COMPONENT_NULL;
        ASSERT_OK(component_from_json(&e, w, "test"));
        ASSERT_STREQ(e.description, "Bare");
        ASSERT_EQ(e.enabled, -1);
        ASSERT_EQ(e.suggest, -1);
        ASSERT_NULL(e.min_version);
        ASSERT_OK(component_from_json(&e, NULL, "test"));
        ASSERT_NULL(e.description);
        ASSERT_EQ(e.enabled, -1);

        /* Bad data is rejected */
        w = sd_json_variant_unref(w);
        ASSERT_OK(sd_json_buildo(&w, SD_JSON_BUILD_PAIR_STRING("minVersion", "not a version!")));
        ASSERT_FAIL(component_from_json(&e, w, "test"));
        w = sd_json_variant_unref(w);
        ASSERT_OK(sd_json_buildo(&w, SD_JSON_BUILD_PAIR_STRV("documentation", STRV_MAKE("ftp://nope"))));
        ASSERT_FAIL(component_from_json(&e, w, "test"));
}

DEFINE_TEST_MAIN(LOG_INFO);

TEST(update_set_flags_to_string) {
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(0), "n/a");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_NEWEST), "current");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED), "current");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_PENDING|UPDATE_NEWEST), "current+pending");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_PARTIAL|UPDATE_PENDING|UPDATE_NEWEST), "current+partial");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_CANDIDATE), "candidate");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_CANDIDATE|UPDATE_PROTECTED), "candidate");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_NEWEST), "available");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED), "installed");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_PROTECTED), "protected");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE), "available");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_PROTECTED), "available");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_NEWEST), "current+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_PROTECTED), "protected+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST), "current+obsolete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE), "installed+obsolete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST), "available+obsolete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_NEWEST), "current+obsolete+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_INCOMPLETE|UPDATE_PROTECTED), "protected+obsolete+incomplete");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_TOO_NEW|UPDATE_NEWEST), "available+too-new");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_INSTALLED|UPDATE_TOO_NEW|UPDATE_NEWEST), "current+too-new");
        ASSERT_STREQ(FORMAT_UPDATE_SET_FLAGS(UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_TOO_NEW), "available+obsolete+too-new");
}
