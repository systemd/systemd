/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "tests.h"
#include "vmspawn-qemu-config.h"

/* Render a single "key = value" pair through qemu_config_key() into an in-memory stream and return both
 * the function's return code and (on success) the rendered bytes. The stream is closed before the buffer
 * is read: open_memstream() may reallocate the buffer on fclose(), so the pointer is only stable after. */
static int render_key(char **ret, const char *key, const char *value) {
        _cleanup_free_ char *buf = NULL;
        size_t sz = 0;
        int r;

        FILE *f = open_memstream(&buf, &sz);
        assert_se(f);

        r = qemu_config_key(f, key, value);
        assert_se(fclose(f) == 0);

        if (r >= 0 && ret)
                *ret = TAKE_PTR(buf);
        return r;
}

static int render_section(char **ret, const char *type, const char *id) {
        _cleanup_free_ char *buf = NULL;
        size_t sz = 0;
        int r;

        FILE *f = open_memstream(&buf, &sz);
        assert_se(f);

        r = qemu_config_section(f, type, id);
        assert_se(fclose(f) == 0);

        if (r >= 0 && ret)
                *ret = TAKE_PTR(buf);
        return r;
}

TEST(qemu_config_key_valid) {
        _cleanup_free_ char *out = NULL;

        ASSERT_OK(render_key(&out, "readonly", "on"));
        ASSERT_STREQ(out, "  readonly = \"on\"\n");

        /* Keys may carry the full identifier charset. */
        out = mfree(out);
        ASSERT_OK(render_key(&out, "confidential-guest-support", "snp0"));
        ASSERT_STREQ(out, "  confidential-guest-support = \"snp0\"\n");
}

TEST(qemu_config_value_permits_path_bytes) {
        _cleanup_free_ char *out = NULL;

        /* Legitimate path bytes, including backslash, must pass through a quoted value verbatim. */
        ASSERT_OK(render_key(&out, "file", "/usr/share/edk2/ovmf/OVMF_CODE.fd"));
        ASSERT_STREQ(out, "  file = \"/usr/share/edk2/ovmf/OVMF_CODE.fd\"\n");

        out = mfree(out);
        ASSERT_OK(render_key(&out, "file", "/weird/but\\legal/path"));
        ASSERT_STREQ(out, "  file = \"/weird/but\\legal/path\"\n");

        /* '=', spaces, brackets etc. are all fine inside a quoted value. */
        out = mfree(out);
        ASSERT_OK(render_key(&out, "cpus", "1,sockets=1"));
        ASSERT_STREQ(out, "  cpus = \"1,sockets=1\"\n");
}

TEST(qemu_config_value_rejects_quote_and_newline) {
        /* These two bytes are the only ones that can break out of the quoted token; both must be refused. */
        ASSERT_ERROR(render_key(NULL, "file", "ab\"cd"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "file", "ab\ncd"), EINVAL);
}

TEST(qemu_config_key_name_rejects_structure) {
        /* Key names are emitted unquoted, so they must be plain identifiers. */
        ASSERT_ERROR(render_key(NULL, "fo=o", "v"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "fo\no", "v"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "fo\"o", "v"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "fo o", "v"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "foo]", "v"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "/foo", "v"), EINVAL);
        ASSERT_ERROR(render_key(NULL, "", "v"), EINVAL);
}

TEST(qemu_config_section_valid) {
        _cleanup_free_ char *out = NULL;

        ASSERT_OK(render_section(&out, "drive", "ovmf-code"));
        ASSERT_STREQ(out, "\n[drive \"ovmf-code\"]\n");

        out = mfree(out);
        ASSERT_OK(render_section(&out, "smp-opts", NULL));
        ASSERT_STREQ(out, "\n[smp-opts]\n");
}

TEST(qemu_config_section_type_rejects_structure) {
        /* The section type is emitted unquoted as "[type]" — a ']' or newline here would let a caller
         * close the header early or open a new section. */
        ASSERT_ERROR(render_section(NULL, "drive]", "id"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "dr\nive", "id"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "dr ive", "id"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "dr\"ive", "id"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "", "id"), EINVAL);
}

TEST(qemu_config_section_id_rejects_structure) {
        /* The id is quoted, but ']' and backslash are still hardened against future runtime data. */
        ASSERT_ERROR(render_section(NULL, "drive", "i\"d"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "drive", "i\nd"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "drive", "i]d"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "drive", "i\\d"), EINVAL);
        ASSERT_ERROR(render_section(NULL, "drive", ""), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
