/* SPDX-License-Identifier: LGPL-2.1+ */

#include "path-lookup.h"
#include "strv.h"
#include "tests.h"
#include "unit-file.h"

static void test_unit_validate_alias_symlink_and_warn(void) {
        log_info("/* %s */", __func__);

        assert_se(unit_validate_alias_symlink_and_warn("/path/a.service", "/other/b.service") == 0);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a.service", "/other/b.socket") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a.service", "/other/b.foobar") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@.service", "/other/b@.service") == 0);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@.service", "/other/b@.socket") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@XXX.service", "/other/b@YYY.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@XXX.service", "/other/b@YYY.socket") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@.service", "/other/b@YYY.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@XXX.service", "/other/b@XXX.service") == 0);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@XXX.service", "/other/b@.service") == 0);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@.service", "/other/b.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a.service", "/other/b@.service") == -EXDEV);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a@.slice", "/other/b.slice") == -EINVAL);
        assert_se(unit_validate_alias_symlink_and_warn("/path/a.slice", "/other/b.slice") == -EINVAL);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_unit_validate_alias_symlink_and_warn();

        return 0;
}
