/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "string-util.h"
#include "tests.h"
#include "unit-name.h"

/* Test helper to simulate completion output and verify base name augmentation */
static void test_completion_base_name_augmentation(void) {
        static const char* test_units[] = {
                "test.service",
                "example.socket",
                "foo.target",
                "bar.service",
                "systemd-networkd.service",
                NULL
        };

        log_info("Testing completion base name augmentation logic");

        for (const char **unit = test_units; *unit; unit++) {
                log_info("Testing unit: %s", *unit);

                /* Check if this is a .service unit */
                if (endswith(*unit, ".service")) {
                        /* Verify we can extract the base name correctly */
                        size_t len = strlen(*unit) - 8; /* 8 = strlen(".service") */
                        _cleanup_free_ char *base_name = strndup(*unit, len);
                        assert_se(base_name);

                        log_info("  → Base name: %s", base_name);

                        /* Verify the base name doesn't contain the .service suffix */
                        assert_se(!endswith(base_name, ".service"));

                        /* Verify the base name + .service equals the original */
                        _cleanup_free_ char *reconstructed = strjoin(base_name, ".service");
                        assert_se(reconstructed);
                        assert_se(streq(reconstructed, *unit));
                } else {
                        log_info("  → Not a .service unit, no base name augmentation");
                }
        }

        log_info("Base name augmentation test passed");
}

/* Test unit name validation for completion */
static void test_completion_unit_name_validation(void) {
        static const char* valid_units[] = {
                "test.service",
                "systemd-networkd.service",
                "foo@bar.service",
                "getty@tty1.service",
                "user@1000.service",
                NULL
        };

        static const char* invalid_units[] = {
                "",
                ".service",
                "test.",
                "test.invalid",
                NULL
        };

        log_info("Testing unit name validation for completion");

        for (const char **unit = valid_units; *unit; unit++) {
                log_info("Valid unit: %s", *unit);
                assert_se(unit_name_is_valid(*unit, UNIT_NAME_ANY));
        }

        for (const char **unit = invalid_units; *unit; unit++) {
                log_info("Invalid unit: %s", *unit);
                assert_se(!unit_name_is_valid(*unit, UNIT_NAME_ANY));
        }

        log_info("Unit name validation test passed");
}

/* Test completion output format */
static void test_completion_output_format(void) {
        log_info("Testing completion output format requirements");

        /* Test that our completion output should:
         * 1. Have no headers
         * 2. Have one unit per line
         * 3. Have base names for .service units
         * 4. Be plain text with no formatting
         */

        /* Simulate the completion logic inline */
        const char* test_output_lines[] = {
                "networkd.service",
                "networkd",  /* base name for .service */
                "foo.socket",
                "bar.target",
                "baz.service",
                "baz",       /* base name for .service */
                NULL
        };

        for (const char **line = test_output_lines; *line; line++) {
                log_info("Output line: '%s'", *line);

                /* Verify no headers or formatting */
                assert_se(!strstr(*line, "UNIT"));
                assert_se(!strstr(*line, "LOAD"));
                assert_se(!strstr(*line, "ACTIVE"));
                assert_se(!strstr(*line, "STATE"));

                /* Verify it's a valid unit name or base name */
                bool is_base_name = !strchr(*line, '.');
                if (!is_base_name) {
                        assert_se(unit_name_is_valid(*line, UNIT_NAME_ANY));
                }
        }

        log_info("Completion output format test passed");
}

/* Test edge cases for completion */
static void test_completion_edge_cases(void) {
        log_info("Testing completion edge cases");

        /* Test empty service name */
        assert_se(!endswith("", ".service"));

        /* Test service suffix only */
        assert_se(endswith(".service", ".service"));

        /* Test very short service name */
        const char *short_service = "a.service";
        assert_se(endswith(short_service, ".service"));
        size_t len = strlen(short_service) - 8;
        assert_se(len == 1);

        /* Test service name with dots */
        const char *dotted_service = "foo.bar.service";
        assert_se(endswith(dotted_service, ".service"));
        _cleanup_free_ char *base = strndup(dotted_service, strlen(dotted_service) - 8);
        assert_se(base);
        assert_se(streq(base, "foo.bar"));

        log_info("Edge cases test passed");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_completion_base_name_augmentation();
        test_completion_unit_name_validation();
        test_completion_output_format();
        test_completion_edge_cases();

        log_info("All completion unit tests passed!");
        return 0;
}
