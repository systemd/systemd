/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "architecture.h"
#include "errno-util.h"
#include "log.h"
#include "tests.h"
#include "util.h"
#include "virt.h"

int main(int argc, char *argv[]) {
        Virtualization v;
        Architecture a;
        const char *p;

        test_setup_logging(LOG_INFO);

        assert_se(architecture_from_string("") < 0);
        assert_se(architecture_from_string(NULL) < 0);
        assert_se(architecture_from_string("hoge") < 0);
        assert_se(architecture_to_string(-1) == NULL);
        assert_se(architecture_from_string(architecture_to_string(0)) == 0);
        assert_se(architecture_from_string(architecture_to_string(1)) == 1);

        v = detect_virtualization();
        if (v < 0 && ERRNO_IS_PRIVILEGE(v))
                return log_tests_skipped("Cannot detect virtualization");

        assert_se(v >= 0);

        log_info("virtualization=%s id=%s",
                 VIRTUALIZATION_IS_CONTAINER(v) ? "container" :
                 VIRTUALIZATION_IS_VM(v)        ? "vm" : "n/a",
                 virtualization_to_string(v));

        a = uname_architecture();
        assert_se(a >= 0);

        p = architecture_to_string(a);
        assert_se(p);
        log_info("uname architecture=%s", p);
        assert_se(architecture_from_string(p) == a);

        a = native_architecture();
        assert_se(a >= 0);

        p = architecture_to_string(a);
        assert_se(p);
        log_info("native architecture=%s", p);
        assert_se(architecture_from_string(p) == a);

        log_info("primary library architecture=" LIB_ARCH_TUPLE);

        return 0;
}
