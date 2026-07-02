/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "fileio.h"
#include "path-util.h"
#include "rm-rf.h"
#include "set.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "vmspawn-util.h"

#define _ESCAPE_QEMU_VALUE_CHECK(str, correct, varname) \
        do {                                            \
                _cleanup_free_ char* varname = NULL;    \
                varname = escape_qemu_value(str);       \
                assert(varname);                        \
                assert_se(streq(varname, correct));     \
        } while (0)

#define ESCAPE_QEMU_VALUE_CHECK(str, correct) \
        _ESCAPE_QEMU_VALUE_CHECK(str, correct, conf##__COUNTER__)

TEST(escape_qemu_value) {
        ESCAPE_QEMU_VALUE_CHECK("abcde", "abcde");
        ESCAPE_QEMU_VALUE_CHECK("a,bcde", "a,,bcde");
        ESCAPE_QEMU_VALUE_CHECK(",,,", ",,,,,,");
        ESCAPE_QEMU_VALUE_CHECK("", "");
}

typedef enum TestMapping {
        MAPPING_FLASH_SPLIT,     /* pflash executable + NVRAM template */
        MAPPING_FLASH_STATELESS, /* read-only pflash, no NVRAM */
        MAPPING_FLASH_COMBINED,  /* read-write pflash with the variable store inside the executable */
        MAPPING_MEMORY,          /* mapped into memory, loaded via -bios */
        MAPPING_KERNEL,          /* loaded like a Linux kernel */
} TestMapping;

static void write_descriptor(
                const char *dir,
                const char *name,
                const char *executable,
                const char *format,
                const char *interface_type,
                const char *arch,
                const char *machine,
                TestMapping mapping,
                char **features) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *j = NULL, *p = NULL;

        if (!arch)
                ASSERT_OK(native_arch_as_qemu(&arch));

        bool flash = IN_SET(mapping, MAPPING_FLASH_SPLIT, MAPPING_FLASH_STATELESS, MAPPING_FLASH_COMBINED);

        ASSERT_OK(sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_STRING("description", name),
                        SD_JSON_BUILD_PAIR_STRV("interface-types", STRV_MAKE(interface_type ?: "uefi")),
                        SD_JSON_BUILD_PAIR("mapping", SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("device", flash ? "flash" : mapping == MAPPING_MEMORY ? "memory" : "kernel"),
                                SD_JSON_BUILD_PAIR_CONDITION(!flash, "filename", SD_JSON_BUILD_STRING(executable)),
                                SD_JSON_BUILD_PAIR_CONDITION(mapping == MAPPING_FLASH_STATELESS, "mode", SD_JSON_BUILD_STRING("stateless")),
                                SD_JSON_BUILD_PAIR_CONDITION(mapping == MAPPING_FLASH_COMBINED, "mode", SD_JSON_BUILD_STRING("combined")),
                                SD_JSON_BUILD_PAIR_CONDITION(mapping == MAPPING_FLASH_SPLIT, "nvram-template", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("filename", "/test/vars.fd"),
                                        SD_JSON_BUILD_PAIR_STRING("format", "raw"))),
                                SD_JSON_BUILD_PAIR_CONDITION(flash, "executable", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("filename", executable),
                                        SD_JSON_BUILD_PAIR_STRING("format", format))))),
                        SD_JSON_BUILD_PAIR("targets", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("architecture", arch),
                                SD_JSON_BUILD_PAIR_STRV("machines", STRV_MAKE(machine ?: QEMU_MACHINE_TYPE))))),
                        SD_JSON_BUILD_PAIR_STRV("features", features),
                        SD_JSON_BUILD_PAIR_EMPTY_ARRAY("tags")));

        ASSERT_OK(sd_json_variant_format(v, /* flags= */ 0, &j));
        ASSERT_NOT_NULL(p = path_join(dir, name));
        ASSERT_OK(write_string_file(p, j, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
}

/* Searches with the given feature sets and flags, and asserts that the firmware with the expected
 * executable path is selected, or -ENOENT if expect_path is NULL. Optionally returns the selected config
 * for further assertions. */
static void check_find(char **include, char **exclude, FindOvmfConfigFlags flags, const char *expect_path, OvmfConfig **ret) {
        _cleanup_set_free_ Set *inc = NULL, *exc = NULL;
        _cleanup_(ovmf_config_freep) OvmfConfig *config = NULL;
        int r;

        ASSERT_OK(set_put_strdupv(&inc, include));
        ASSERT_OK(set_put_strdupv(&exc, exclude));

        r = find_ovmf_config(inc, exc, flags, &config, /* ret_firmware_json= */ NULL);
        if (!expect_path)
                ASSERT_ERROR(r, ENOENT);
        else {
                ASSERT_OK(r);
                ASSERT_STREQ(config->path, expect_path);
        }

        if (ret)
                *ret = TAKE_PTR(config);
}

TEST(find_ovmf_config) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_(ovmf_config_freep) OvmfConfig *config = NULL;
        _cleanup_free_ char *dir = NULL;

        if (native_arch_as_qemu(/* ret= */ NULL) < 0)
                return (void) log_tests_skipped("native architecture not supported by qemu");

        ASSERT_OK(mkdtemp_malloc("/tmp/test-vmspawn-firmware-XXXXXX", &tmp));
        ASSERT_OK_ERRNO(setenv("XDG_CONFIG_HOME", tmp, /* overwrite= */ true));
        ASSERT_NOT_NULL(dir = path_join(tmp, "qemu/firmware"));

        /* All fixtures declare made-up features and every search below requires one of them, so
         * descriptors installed on the host can never match and the test stays hermetic. */

        /* Stateful vs. stateless selection, in both sort orders. */
        write_descriptor(dir, "00-a-stateless.json", "/test/a-stateless.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_STATELESS, STRV_MAKE("vmspawn-test-a"));
        write_descriptor(dir, "10-a-stateful.json", "/test/a-stateful.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-a"));
        write_descriptor(dir, "00-b-stateful.json", "/test/b-stateful.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-b"));
        write_descriptor(dir, "10-b-stateless.json", "/test/b-stateless.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_STATELESS, STRV_MAKE("vmspawn-test-b"));

        /* By default only firmware with an NVRAM template is considered. */
        check_find(STRV_MAKE("vmspawn-test-a"), /* exclude= */ NULL, /* flags= */ 0, "/test/a-stateful.fd", &config);
        ASSERT_STREQ(config->vars, "/test/vars.fd");
        ASSERT_STREQ(config->format, "raw");
        ASSERT_FALSE(ovmf_config_is_stateless(config));
        ASSERT_FALSE(ovmf_config_has_feature(config, "secure-boot"));
        config = ovmf_config_free(config);

        /* With FIND_OVMF_STATELESS only firmware in stateless flash mode is considered. */
        check_find(STRV_MAKE("vmspawn-test-a"), /* exclude= */ NULL, FIND_OVMF_STATELESS, "/test/a-stateless.fd", &config);
        ASSERT_NULL(config->vars);
        ASSERT_TRUE(ovmf_config_is_stateless(config));
        config = ovmf_config_free(config);

        check_find(STRV_MAKE("vmspawn-test-b"), /* exclude= */ NULL, /* flags= */ 0, "/test/b-stateful.fd", /* ret= */ NULL);
        check_find(STRV_MAKE("vmspawn-test-b"), /* exclude= */ NULL, FIND_OVMF_STATELESS, "/test/b-stateless.fd", /* ret= */ NULL);

        /* FIND_OVMF_REQUIRE_RAW skips firmware in other formats, which is accepted otherwise. */
        write_descriptor(dir, "00-c-qcow2.json", "/test/c.qcow2", "qcow2", NULL, NULL, NULL, MAPPING_FLASH_STATELESS, STRV_MAKE("vmspawn-test-c"));
        write_descriptor(dir, "10-c-raw.json", "/test/c.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_STATELESS, STRV_MAKE("vmspawn-test-c"));

        check_find(STRV_MAKE("vmspawn-test-c"), /* exclude= */ NULL, FIND_OVMF_STATELESS, "/test/c.qcow2", &config);
        ASSERT_STREQ(config->format, "qcow2");
        config = ovmf_config_free(config);

        check_find(STRV_MAKE("vmspawn-test-c"), /* exclude= */ NULL, FIND_OVMF_STATELESS|FIND_OVMF_REQUIRE_RAW, "/test/c.fd", /* ret= */ NULL);

        /* Memory-mapped firmware (loaded via -bios) is stateless and raw by definition. */
        write_descriptor(dir, "00-m-memory.json", "/test/m-memory.fd", "raw", NULL, NULL, NULL, MAPPING_MEMORY, STRV_MAKE("vmspawn-test-m"));

        check_find(STRV_MAKE("vmspawn-test-m"), /* exclude= */ NULL, /* flags= */ 0, /* expect_path= */ NULL, /* ret= */ NULL);
        check_find(STRV_MAKE("vmspawn-test-m"), /* exclude= */ NULL, FIND_OVMF_STATELESS|FIND_OVMF_REQUIRE_RAW, "/test/m-memory.fd", &config);
        ASSERT_NULL(config->vars);
        ASSERT_NULL(config->format);
        ASSERT_STREQ(ovmf_config_format(config), "raw");
        ASSERT_TRUE(ovmf_config_is_stateless(config));
        config = ovmf_config_free(config);

        /* Combined-mode flash firmware carries a writable variable store inside the executable, it must not be treated as stateless. */
        write_descriptor(dir, "00-f-combined.json", "/test/f-combined.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_COMBINED, STRV_MAKE("vmspawn-test-f"));

        check_find(STRV_MAKE("vmspawn-test-f"), /* exclude= */ NULL, /* flags= */ 0, /* expect_path= */ NULL, /* ret= */ NULL);
        check_find(STRV_MAKE("vmspawn-test-f"), /* exclude= */ NULL, FIND_OVMF_STATELESS, /* expect_path= */ NULL, /* ret= */ NULL);

        /* Firmware that is not UEFI, uses an unsupported mapping device, or doesn't match the native
         * architecture or machine type, is skipped. */
        write_descriptor(dir, "00-d-bios.json", "/test/d-bios.fd", "raw", "bios", NULL, NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-d"));
        write_descriptor(dir, "05-d-kernel.json", "/test/d-kernel.fd", "raw", NULL, NULL, NULL, MAPPING_KERNEL, STRV_MAKE("vmspawn-test-d"));
        write_descriptor(dir, "10-d-arch.json", "/test/d-arch.fd", "raw", NULL, "vmspawn-test-arch", NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-d"));
        write_descriptor(dir, "20-d-machine.json", "/test/d-machine.fd", "raw", NULL, NULL, "vmspawn-test-mach", MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-d"));
        write_descriptor(dir, "30-d-good.json", "/test/d-good.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-d"));

        check_find(STRV_MAKE("vmspawn-test-d"), /* exclude= */ NULL, /* flags= */ 0, "/test/d-good.fd", /* ret= */ NULL);

        /* Feature include/exclude handling. */
        write_descriptor(dir, "00-e-both.json", "/test/e-both.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-e1", "vmspawn-test-e2", "secure-boot"));
        write_descriptor(dir, "10-e-one.json", "/test/e-one.fd", "raw", NULL, NULL, NULL, MAPPING_FLASH_SPLIT, STRV_MAKE("vmspawn-test-e1"));

        /* The first matching descriptor in sort order wins. */
        check_find(STRV_MAKE("vmspawn-test-e1"), /* exclude= */ NULL, /* flags= */ 0, "/test/e-both.fd", &config);
        ASSERT_TRUE(ovmf_config_has_feature(config, "secure-boot"));
        config = ovmf_config_free(config);

        /* Descriptors with an excluded feature are skipped. */
        check_find(STRV_MAKE("vmspawn-test-e1"), STRV_MAKE("vmspawn-test-e2"), /* flags= */ 0, "/test/e-one.fd", &config);
        ASSERT_TRUE(ovmf_config_has_feature(config, "vmspawn-test-e1"));
        ASSERT_FALSE(ovmf_config_has_feature(config, "vmspawn-test-e2"));
        config = ovmf_config_free(config);

        /* Inclusion wins over exclusion. */
        check_find(STRV_MAKE("vmspawn-test-e1", "vmspawn-test-e2"), STRV_MAKE("vmspawn-test-e2"), /* flags= */ 0, "/test/e-both.fd", &config);
        ASSERT_TRUE(ovmf_config_has_feature(config, "vmspawn-test-e1"));
        ASSERT_TRUE(ovmf_config_has_feature(config, "vmspawn-test-e2"));
        config = ovmf_config_free(config);

        /* All included features must be present. */
        check_find(STRV_MAKE("vmspawn-test-e1", "vmspawn-test-nonexistent"), /* exclude= */ NULL, /* flags= */ 0, /* expect_path= */ NULL, /* ret= */ NULL);

        /* The firmware description JSON is returned on request. */
        _cleanup_set_free_ Set *inc = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        ASSERT_OK(set_put_strdup(&inc, "vmspawn-test-a"));
        ASSERT_OK(find_ovmf_config(inc, /* features_exclude= */ NULL, /* flags= */ 0, &config, &json));
        ASSERT_TRUE(sd_json_variant_is_object(json));

        ASSERT_OK_ERRNO(unsetenv("XDG_CONFIG_HOME"));
}

DEFINE_TEST_MAIN(LOG_INFO);
