/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "bus-print-properties.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

static void test_json_output_basic(void) {
        log_info("/* %s */", __func__);

        /* Test basic JSON property output */
        BusPrintPropertyFlags flags = BUS_PRINT_PROPERTY_JSON;

        /* Redirect stdout to capture output */
        FILE *original_stdout = stdout;
        FILE *test_output = tmpfile();
        assert_se(test_output);
        stdout = test_output;

        /* Test simple property */
        bus_print_property_value("TestProperty", NULL, flags, "test-value");
        bus_print_property_json_finish(flags);

        /* Restore stdout and read captured output */
        stdout = original_stdout;
        rewind(test_output);

        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, test_output);
        buffer[bytes_read] = '\0';
        fclose(test_output);

        log_info("JSON output: %s", buffer);

        /* Verify JSON structure */
        assert_se(startswith(buffer, "{"));
        assert_se(endswith(buffer, "}\n"));
        assert_se(strstr(buffer, "\"TestProperty\":"));
        assert_se(strstr(buffer, "\"test-value\""));

        /* Verify it's valid JSON by parsing it */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        assert_se(sd_json_parse(buffer, 0, &v, NULL, NULL) >= 0);
        assert_se(sd_json_variant_is_object(v));
}

static void test_json_pretty_output(void) {
        log_info("/* %s */", __func__);

        /* Test pretty JSON property output */
        BusPrintPropertyFlags flags = BUS_PRINT_PROPERTY_JSON | BUS_PRINT_PROPERTY_JSON_PRETTY;

        /* Redirect stdout to capture output */
        FILE *original_stdout = stdout;
        FILE *test_output = tmpfile();
        assert_se(test_output);
        stdout = test_output;

        /* Test multiple properties */
        bus_print_property_value("Property1", NULL, flags, "value1");
        bus_print_property_value("Property2", NULL, flags, "value2");
        bus_print_property_json_finish(flags);

        /* Restore stdout and read captured output */
        stdout = original_stdout;
        rewind(test_output);

        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, test_output);
        buffer[bytes_read] = '\0';
        fclose(test_output);

        log_info("Pretty JSON output: %s", buffer);

        /* Verify pretty formatting */
        assert_se(startswith(buffer, "{\n"));
        assert_se(endswith(buffer, "\n}\n"));
        assert_se(strstr(buffer, "  \"Property1\": "));
        assert_se(strstr(buffer, ",\n"));

        /* Verify it's valid JSON */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        assert_se(sd_json_parse(buffer, 0, &v, NULL, NULL) >= 0);
        assert_se(sd_json_variant_is_object(v));
}

static void test_json_compact_output(void) {
        log_info("/* %s */", __func__);

        /* Test compact JSON property output */
        BusPrintPropertyFlags flags = BUS_PRINT_PROPERTY_JSON;

        /* Redirect stdout to capture output */
        FILE *original_stdout = stdout;
        FILE *test_output = tmpfile();
        assert_se(test_output);
        stdout = test_output;

        /* Test multiple properties */
        bus_print_property_value("Prop1", NULL, flags, "val1");
        bus_print_property_value("Prop2", NULL, flags, "val2");
        bus_print_property_json_finish(flags);

        /* Restore stdout and read captured output */
        stdout = original_stdout;
        rewind(test_output);

        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, test_output);
        buffer[bytes_read] = '\0';
        fclose(test_output);

        log_info("Compact JSON output: %s", buffer);

        /* Verify compact formatting (no extra whitespace) */
        assert_se(startswith(buffer, "{"));
        assert_se(endswith(buffer, "}\n"));
        assert_se(!strstr(buffer, "{\n"));  /* Should not have newline after opening brace */
        assert_se(strstr(buffer, "\"Prop1\":"));  /* Should not have space around colon */

        /* Verify it's valid JSON */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        assert_se(sd_json_parse(buffer, 0, &v, NULL, NULL) >= 0);
        assert_se(sd_json_variant_is_object(v));
}

static void test_json_special_characters(void) {
        log_info("/* %s */", __func__);

        /* Test JSON escaping of special characters */
        BusPrintPropertyFlags flags = BUS_PRINT_PROPERTY_JSON;

        /* Redirect stdout to capture output */
        FILE *original_stdout = stdout;
        FILE *test_output = tmpfile();
        assert_se(test_output);
        stdout = test_output;

        /* Test property with special characters that need escaping */
        bus_print_property_value("TestQuotes", NULL, flags, "value with \"quotes\" and \\ backslash");
        bus_print_property_value("TestNewlines", NULL, flags, "line1\nline2");
        bus_print_property_json_finish(flags);

        /* Restore stdout and read captured output */
        stdout = original_stdout;
        rewind(test_output);

        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, test_output);
        buffer[bytes_read] = '\0';
        fclose(test_output);

        log_info("JSON with special chars: %s", buffer);

        /* Verify it's valid JSON despite special characters */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        assert_se(sd_json_parse(buffer, 0, &v, NULL, NULL) >= 0);
        assert_se(sd_json_variant_is_object(v));

        /* Verify escaping */
        assert_se(strstr(buffer, "\\\""));  /* Escaped quotes */
        assert_se(strstr(buffer, "\\\\"));  /* Escaped backslash */
}

static void test_json_empty_values(void) {
        log_info("/* %s */", __func__);

        /* Test JSON handling of empty/null values */
        BusPrintPropertyFlags flags = BUS_PRINT_PROPERTY_JSON | BUS_PRINT_PROPERTY_SHOW_EMPTY;

        /* Redirect stdout to capture output */
        FILE *original_stdout = stdout;
        FILE *test_output = tmpfile();
        assert_se(test_output);
        stdout = test_output;

        /* Test empty and null values */
        bus_print_property_value("EmptyString", NULL, flags, "");
        bus_print_property_value("NullValue", NULL, flags, NULL);
        bus_print_property_json_finish(flags);

        /* Restore stdout and read captured output */
        stdout = original_stdout;
        rewind(test_output);

        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, test_output);
        buffer[bytes_read] = '\0';
        fclose(test_output);

        log_info("JSON with empty values: %s", buffer);

        /* Verify null handling */
        assert_se(strstr(buffer, "null"));

        /* Verify it's valid JSON */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        assert_se(sd_json_parse(buffer, 0, &v, NULL, NULL) >= 0);
        assert_se(sd_json_variant_is_object(v));
}

static void test_regular_output_unchanged(void) {
        log_info("/* %s */", __func__);

        /* Test that regular output is not affected by JSON additions */
        BusPrintPropertyFlags flags = 0;  /* No JSON flags */

        /* Redirect stdout to capture output */
        FILE *original_stdout = stdout;
        FILE *test_output = tmpfile();
        assert_se(test_output);
        stdout = test_output;

        /* Test regular property output */
        bus_print_property_value("TestProperty", NULL, flags, "test-value");

        /* Restore stdout and read captured output */
        stdout = original_stdout;
        rewind(test_output);

        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, test_output);
        buffer[bytes_read] = '\0';
        fclose(test_output);

        log_info("Regular output: %s", buffer);

        /* Verify traditional key=value format */
        assert_se(strstr(buffer, "TestProperty=test-value"));
        assert_se(endswith(buffer, "\n"));
        assert_se(!strstr(buffer, "{"));  /* Should not contain JSON */
        assert_se(!strstr(buffer, "\""));  /* Should not contain quotes */
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_json_output_basic();
        test_json_pretty_output();
        test_json_compact_output();
        test_json_special_characters();
        test_json_empty_values();
        test_regular_output_unchanged();

        return 0;
}