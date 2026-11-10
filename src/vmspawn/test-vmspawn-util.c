/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "fileio.h"
#include "json-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "vmspawn-util.h"

#define _ESCAPE_QEMU_VALUE_CHECK(str, correct, varname)                                 \
        do {                                                                            \
                _cleanup_free_ char* varname = ASSERT_NOT_NULL(escape_qemu_value(str)); \
                ASSERT_STREQ(varname, correct);                                         \
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
        MAPPING_FLASH_SPLIT,      /* pflash executable + NVRAM template */
        MAPPING_FLASH_STATELESS,  /* read-only pflash, no NVRAM */
        MAPPING_FLASH_COMBINED,   /* read-write pflash with the variable store inside the executable */
        MAPPING_MEMORY,           /* mapped into memory, loaded via -bios */
        MAPPING_MEMORY_UEFI_VARS, /* mapped into memory, with a template for QEMU's UEFI variable store */
        MAPPING_KERNEL,           /* loaded like a Linux kernel */
} TestMapping;

static void write_descriptor(
                const char *dir,
                const char *name,
                const char *executable,
                const char *format,
                char **interface_types,
                const char *arch,
                const char *machine,
                TestMapping mapping,
                char **features) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *p = NULL;

        if (!arch)
                ASSERT_OK(native_arch_as_qemu(&arch));

        bool flash = IN_SET(mapping, MAPPING_FLASH_SPLIT, MAPPING_FLASH_STATELESS, MAPPING_FLASH_COMBINED);
        bool memory = IN_SET(mapping, MAPPING_MEMORY, MAPPING_MEMORY_UEFI_VARS);

        ASSERT_OK(sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_STRING("description", name),
                        SD_JSON_BUILD_PAIR_STRV("interface-types", interface_types ?: STRV_MAKE("uefi")),
                        SD_JSON_BUILD_PAIR("mapping", SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("device", flash ? "flash" : memory ? "memory" : "kernel"),
                                SD_JSON_BUILD_PAIR_CONDITION(!flash, "filename", SD_JSON_BUILD_STRING(executable)),
                                SD_JSON_BUILD_PAIR_CONDITION(mapping == MAPPING_MEMORY_UEFI_VARS, "uefi-vars", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("template", "/test/vars.json"))),
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

        ASSERT_NOT_NULL(p = path_join(dir, name));
        ASSERT_OK(json_variant_write_file_at(AT_FDCWD, p, v, /* format_flags= */ 0, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
}

/* Firmware discovery is tested in two steps: all descriptors listed in test_descriptors are installed,
 * and then each search in test_searches is run against them and must find exactly the descriptors it
 * expects. To test something new, add the descriptors it needs and add them to the expected results of
 * every search that should find them, then add the searches it needs.
 *
 * All descriptors declare the made-up "vmspawn-test" feature and every search requires it, so
 * descriptors installed on the host never match. */

typedef struct TestDescriptor {
        const char *name;                     /* installed as <name>.json, executable /test/<name> */
        TestMapping mapping;
        const char *format;                   /* executable format of flash mappings, default "raw" */
        const char * const *interface_types;  /* default "uefi" */
        const char *arch;                     /* default the native architecture */
        const char *machine;                  /* default the native machine type */
        const char * const *features;         /* in addition to "vmspawn-test" */
} TestDescriptor;

static const TestDescriptor test_descriptors[] = {
        /* Found by some of the searches. */
        { "flash-split",             MAPPING_FLASH_SPLIT                                                        },
        { "flash-split-qcow2",       MAPPING_FLASH_SPLIT,      .format = "qcow2"                                },
        { "flash-split-secure-boot", MAPPING_FLASH_SPLIT,      .features = STRV_MAKE_CONST("secure-boot")       },
        { "flash-stateless",         MAPPING_FLASH_STATELESS                                                    },
        { "flash-stateless-qcow2",   MAPPING_FLASH_STATELESS,  .format = "qcow2"                                },
        { "memory",                  MAPPING_MEMORY                                                             },
        { "memory-secure-boot",      MAPPING_MEMORY,           .features = STRV_MAKE_CONST("secure-boot")       },
        { "memory-host-uefi-vars",   MAPPING_MEMORY_UEFI_VARS, .features = STRV_MAKE_CONST("host-uefi-vars")    },

        /* Never found. Each differs from one of the above in a single property, which rules it out. */
        { "bios",                    MAPPING_FLASH_SPLIT,      .interface_types = STRV_MAKE_CONST("bios")       },
        { "foreign-arch",            MAPPING_FLASH_SPLIT,      .arch = "vmspawn-test-arch"                      },
        { "foreign-machine",         MAPPING_FLASH_SPLIT,      .machine = "vmspawn-test-machine"                },
        { "flash-combined",          MAPPING_FLASH_COMBINED                                                     }, /* writable variable store */
        { "kernel",                  MAPPING_KERNEL                                                             }, /* unsupported device */
        { "memory-host-uefi-vars-without-template",
                                     MAPPING_MEMORY,           .features = STRV_MAKE_CONST("host-uefi-vars")    },
        { "flash-stateless-host-uefi-vars",
                                     MAPPING_FLASH_STATELESS,  .features = STRV_MAKE_CONST("host-uefi-vars")    },
};

#define TEST_FLAGS_COCO (FIND_OVMF_STATELESS|FIND_OVMF_REQUIRE_RAW) /* as vmspawn searches under --coco= */

typedef struct TestSearch {
        const char *description;
        FindOvmfConfigFlags flags;
        const char * const *include;          /* in addition to "vmspawn-test" */
        const char * const *exclude;
        const char * const *expect;           /* names of the descriptors found, in any order */
        const char * const *expect_uefi_vars; /* found too if QEMU provides a host-side UEFI variable store */
} TestSearch;

static const TestSearch test_searches[] = {
        {
                .description      = "firmware with a variable store",
                .flags            = 0,
                .expect           = STRV_MAKE_CONST("flash-split", "flash-split-qcow2", "flash-split-secure-boot"),
                .expect_uefi_vars = STRV_MAKE_CONST("memory-host-uefi-vars"),
        },
        {
                .description      = "stateless firmware",
                .flags            = FIND_OVMF_STATELESS,
                .expect           = STRV_MAKE_CONST("flash-stateless", "flash-stateless-qcow2", "memory", "memory-secure-boot"),
        },
        {
                .description      = "stateless firmware in raw format",
                .flags            = TEST_FLAGS_COCO,
                .expect           = STRV_MAKE_CONST("flash-stateless", "memory", "memory-secure-boot"),
        },
        {
                .description      = "stateless firmware in raw format, with Secure Boot",
                .flags            = TEST_FLAGS_COCO,
                .include          = STRV_MAKE_CONST("secure-boot"),
                .expect           = STRV_MAKE_CONST("memory-secure-boot"),
        },
        {
                .description      = "firmware with a variable store and Secure Boot",
                .flags            = 0,
                .include          = STRV_MAKE_CONST("secure-boot"),
                .expect           = STRV_MAKE_CONST("flash-split-secure-boot"),
        },
        {
                .description      = "firmware with a variable store, without Secure Boot",
                .flags            = 0,
                .exclude          = STRV_MAKE_CONST("secure-boot"),
                .expect           = STRV_MAKE_CONST("flash-split", "flash-split-qcow2"),
                .expect_uefi_vars = STRV_MAKE_CONST("memory-host-uefi-vars"),
        },
        {
                .description      = "a feature both required and excluded, which is required then",
                .flags            = 0,
                .include          = STRV_MAKE_CONST("secure-boot"),
                .exclude          = STRV_MAKE_CONST("secure-boot"),
                .expect           = STRV_MAKE_CONST("flash-split-secure-boot"),
        },
        {
                .description      = "a feature no firmware has",
                .flags            = 0,
                .include          = STRV_MAKE_CONST("vmspawn-test-missing"),
                .expect           = NULL,
        },
};

/* Descriptors that describe stateless firmware, as told by ovmf_config_is_stateless(). */
static const char * const *test_descriptors_stateless = STRV_MAKE_CONST(
                "flash-stateless", "flash-stateless-qcow2", "memory", "memory-secure-boot");

static const TestDescriptor* test_descriptor_find(const char *name) {
        FOREACH_ELEMENT(d, test_descriptors)
                if (streq(d->name, name))
                        return d;

        log_error("Unknown test descriptor '%s'", name);
        return NULL;
}

static char* test_descriptor_path(const char *dir, const TestDescriptor *d) {
        return strjoin(dir, "/", d->name, ".json");
}

/* Appends the descriptor paths of the named test descriptors to l. */
static void test_descriptor_paths_extend(char ***l, const char *dir, const char * const *names) {
        assert(l);
        assert(dir);

        STRV_FOREACH(name, (char**) names) {
                const TestDescriptor *d;

                ASSERT_NOT_NULL(d = test_descriptor_find(*name));
                ASSERT_OK(strv_consume(l, test_descriptor_path(dir, d)));
        }
}

static char* test_descriptor_executable(const TestDescriptor *d) {
        return strjoin("/test/", d->name);
}

/* Installs test_descriptors as the user's firmware descriptors. */
static void install_test_descriptors(char **ret_tmp, char **ret_dir) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *dir = NULL;

        assert(ret_tmp);
        assert(ret_dir);

        ASSERT_OK(mkdtemp_malloc("/tmp/test-vmspawn-firmware-XXXXXX", &tmp));
        ASSERT_OK_ERRNO(setenv("XDG_CONFIG_HOME", tmp, /* overwrite= */ true));
        ASSERT_NOT_NULL(dir = path_join(tmp, "qemu/firmware"));

        FOREACH_ELEMENT(d, test_descriptors) {
                _cleanup_free_ char *name = NULL, *executable = NULL;
                _cleanup_strv_free_ char **features = NULL;

                ASSERT_NOT_NULL(name = strjoin(d->name, ".json"));
                ASSERT_NOT_NULL(executable = test_descriptor_executable(d));
                ASSERT_NOT_NULL(features = strv_new("vmspawn-test"));
                ASSERT_OK(strv_extend_strv(&features, (char**) d->features, /* filter_duplicates= */ false));

                write_descriptor(dir, name, executable, d->format ?: "raw", (char**) d->interface_types,
                                 d->arch, d->machine, d->mapping, features);
        }

        *ret_tmp = TAKE_PTR(tmp);
        *ret_dir = TAKE_PTR(dir);
}

/* Loading a descriptor reproduces what it declares. */
TEST(load_ovmf_config) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *dir = NULL;

        if (native_arch_as_qemu(/* ret= */ NULL) < 0)
                return (void) log_tests_skipped("native architecture not supported by qemu");

        STRV_FOREACH(name, (char**) test_descriptors_stateless)
                ASSERT_NOT_NULL(test_descriptor_find(*name));

        install_test_descriptors(&tmp, &dir);

        FOREACH_ELEMENT(d, test_descriptors) {
                _cleanup_(ovmf_config_freep) OvmfConfig *config = NULL;
                _cleanup_free_ char *path = NULL, *executable = NULL;

                log_info("Loading test descriptor '%s'", d->name);
                ASSERT_NOT_NULL(path = test_descriptor_path(dir, d));

                if (d->mapping == MAPPING_KERNEL) {
                        ASSERT_ERROR(load_ovmf_config(path, &config), EOPNOTSUPP);
                        continue;
                }

                ASSERT_OK(load_ovmf_config(path, &config));

                bool flash = IN_SET(d->mapping, MAPPING_FLASH_SPLIT, MAPPING_FLASH_STATELESS, MAPPING_FLASH_COMBINED);
                bool split = d->mapping == MAPPING_FLASH_SPLIT;
                bool uefi_vars = d->mapping == MAPPING_MEMORY_UEFI_VARS;

                ASSERT_NOT_NULL(executable = test_descriptor_executable(d));
                ASSERT_STREQ(config->path, executable);
                /* Firmware not mapped into flash carries no format and is raw by definition. */
                ASSERT_STREQ(ovmf_config_format(config), flash ? d->format ?: "raw" : "raw");
                ASSERT_STREQ(config->vars, split ? "/test/vars.fd" : NULL);
                ASSERT_STREQ(config->uefi_vars_template, uefi_vars ? "/test/vars.json" : NULL);

                ASSERT_EQ(ovmf_config_is_stateless(config), strv_contains((char**) test_descriptors_stateless, d->name));
                ASSERT_EQ(ovmf_config_has_host_uefi_vars(config), strv_contains((char**) d->features, "host-uefi-vars"));
                ASSERT_EQ(ovmf_config_has_feature(config, "secure-boot"), strv_contains((char**) d->features, "secure-boot"));
        }

        ASSERT_OK_ERRNO(unsetenv("XDG_CONFIG_HOME"));
}

/* Each search finds exactly the expected descriptors, and automatic selection picks the first of them. */
TEST(list_eligible_ovmf_config) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_free_ char *dir = NULL;

        if (native_arch_as_qemu(/* ret= */ NULL) < 0)
                return (void) log_tests_skipped("native architecture not supported by qemu");

        install_test_descriptors(&tmp, &dir);

        FOREACH_ELEMENT(search, test_searches) {
                _cleanup_strv_free_ char **found = NULL, **expected = NULL;
                _cleanup_set_free_ Set *include = NULL, *exclude = NULL;
                _cleanup_(ovmf_config_freep) OvmfConfig *config = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
                int r;

                log_info("Searching for %s", search->description);

                test_descriptor_paths_extend(&expected, dir, search->expect);
                if (QEMU_UEFI_VARS_DEVICE)
                        test_descriptor_paths_extend(&expected, dir, search->expect_uefi_vars);

                ASSERT_OK(set_put_strdup(&include, "vmspawn-test"));
                ASSERT_OK(set_put_strdupv(&include, (char**) search->include));
                ASSERT_OK(set_put_strdupv(&exclude, (char**) search->exclude));

                ASSERT_OK(list_eligible_ovmf_config(include, exclude, search->flags, &found,
                                                    /* ret_first= */ NULL, /* ret_first_json= */ NULL));

                r = find_ovmf_config(include, exclude, search->flags, &config, &json);
                if (strv_isempty(found))
                        ASSERT_ERROR(r, ENOENT);
                else {
                        _cleanup_free_ char *selected = NULL;
                        const char *name;

                        /* Map the selected executable /test/<name> back to its descriptor. */
                        ASSERT_OK(r);
                        ASSERT_NOT_NULL(name = startswith(config->path, "/test/"));
                        ASSERT_NOT_NULL(selected = strjoin(dir, "/", name, ".json"));
                        ASSERT_STREQ(selected, found[0]);
                        /* write_descriptor() names the descriptor after its file. */
                        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(json, "description")),
                                     last_path_component(found[0]));
                }

                /* All descriptors live in one directory, so the order of preference is by file name. */
                strv_sort(expected);
                if (!strv_equal(found, expected)) {
                        _cleanup_free_ char *f = strv_join(found, "\n  "), *e = strv_join(expected, "\n  ");
                        log_error("Searching for %s found:\n  %s\nbut expected:\n  %s", search->description, strnull(f), strnull(e));
                }
                ASSERT_TRUE(strv_equal(found, expected));
        }

        ASSERT_OK_ERRNO(unsetenv("XDG_CONFIG_HOME"));
}

DEFINE_TEST_MAIN(LOG_INFO);
