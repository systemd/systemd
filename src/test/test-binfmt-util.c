/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "binfmt-util.h"
#include "tests.h"

TEST(binfmt_mounted_and_writable) {
        ASSERT_OK(binfmt_mounted_and_writable());
}

static void test_rule_parse_one(
                const char *s,
                const char *name,
                BinfmtRuleType type,
                const char *interpreter,
                const char *bpf_handler) {

        _cleanup_(binfmt_rule_done) BinfmtRule rule = {};

        log_debug("/* %s(%s) */", __func__, s);

        ASSERT_OK(binfmt_rule_parse(s, &rule));
        ASSERT_STREQ(rule.name, name);
        ASSERT_EQ(rule.type, type);
        ASSERT_STREQ(rule.interpreter, interpreter);
        ASSERT_STREQ(rule.bpf_handler, bpf_handler);
}

TEST(binfmt_rule_parse) {
        BinfmtRule rule = {};

        test_rule_parse_one(":DOSWin:M::MZ::/usr/bin/wine:", "DOSWin", BINFMT_RULE_MAGIC, "/usr/bin/wine", /* bpf_handler= */ NULL);
        test_rule_parse_one(":qemu-arm:M:0:\\x7fELF:\\xff\\xff:/usr/bin/qemu-arm:FP", "qemu-arm", BINFMT_RULE_MAGIC, "/usr/bin/qemu-arm", /* bpf_handler= */ NULL);
        test_rule_parse_one(",Java,E,,jar,,/usr/bin/jexec,", "Java", BINFMT_RULE_EXTENSION, "/usr/bin/jexec", /* bpf_handler= */ NULL);

        /* bpf-backed rules name a handler instead of an interpreter */
        test_rule_parse_one(":qemu:B::::my_handler:D", "qemu", BINFMT_RULE_BPF, /* interpreter= */ NULL, "my_handler");

        /* Missing trailing fields are empty, the kernel refuses these rules when they are written */
        test_rule_parse_one(":DOSWin:M::MZ::/usr/bin/wine", "DOSWin", BINFMT_RULE_MAGIC, "/usr/bin/wine", /* bpf_handler= */ NULL);
        test_rule_parse_one(":qemu:B::::my_handler", "qemu", BINFMT_RULE_BPF, /* interpreter= */ NULL, "my_handler");
        test_rule_parse_one(":x:B", "x", BINFMT_RULE_BPF, /* interpreter= */ NULL, "");

        /* Unknown types are left to the kernel to refuse */
        test_rule_parse_one(":x:BB::::h:", "x", _BINFMT_RULE_TYPE_INVALID, "h", /* bpf_handler= */ NULL);
        test_rule_parse_one(":x", "x", _BINFMT_RULE_TYPE_INVALID, "", /* bpf_handler= */ NULL);

        ASSERT_ERROR(binfmt_rule_parse("", &rule), EINVAL);
        ASSERT_NULL(rule.buffer);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
