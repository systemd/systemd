/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "analyze-verify-util.h"
#include "analyze-verify-varlink.h"
#include "json-util.h"
#include "log.h"
#include "runtime-scope.h"
#include "strv.h"
#include "varlink-io.systemd.Analyze.h"
#include "varlink-util.h"

#define VERIFY_INPUT_FILENAMES_MAX       4096U
#define VERIFY_INPUT_FILENAME_BYTES_MAX  (1U * 1024U * 1024U)
#define VERIFY_UNIT_NAME_MAP_MAX         65536U
#define VERIFY_DIAGNOSTICS_MAX           4096U
#define VERIFY_DIAGNOSTIC_BYTES_MAX      (1U * 1024U * 1024U)
#define VERIFY_REPLY_BYTES_MAX           (8U * 1024U * 1024U)

typedef struct VerifyParameters {
        char **unit_files;
} VerifyParameters;

static void verify_parameters_done(VerifyParameters *p) {
        assert(p);

        p->unit_files = strv_free(p->unit_files);
}

static const char* diagnostic_severity(int priority) {
        priority = LOG_PRI(priority);

        if (priority <= LOG_ERR)
                return "error";
        if (priority == LOG_WARNING)
                return "warning";
        if (priority == LOG_NOTICE)
                return "notice";

        return "info";
}

static int verify_result_build_parameters(
                const VerifyUnitsResult *result,
                sd_json_variant **ret) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(result);
        assert(ret);

        FOREACH_ARRAY(diagnostic, result->diagnostics.items, result->diagnostics.n_items) {
                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_STRING(
                                                "severity", diagnostic_severity(diagnostic->priority)),
                                SD_JSON_BUILD_PAIR_STRING("message", diagnostic->message),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                !!diagnostic->unit,
                                                "unit",
                                                SD_JSON_BUILD_STRING(diagnostic->unit)),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                !!diagnostic->configuration_file,
                                                "configurationFile",
                                                SD_JSON_BUILD_STRING(diagnostic->configuration_file)),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                diagnostic->configuration_line > 0,
                                                "configurationLine",
                                                SD_JSON_BUILD_UNSIGNED(diagnostic->configuration_line)),
                                SD_JSON_BUILD_PAIR_CONDITION(
                                                !!diagnostic->message_id,
                                                "messageId",
                                                SD_JSON_BUILD_STRING(diagnostic->message_id)));
                if (r < 0)
                        return r;
        }

        if (!array) {
                r = sd_json_variant_new_array(&array, /* array= */ NULL, /* n= */ 0);
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR_VARIANT("diagnostics", array));
}

int verify_result_build_varlink_reply(
                const VerifyUnitsResult *result,
                size_t size_max,
                sd_json_variant **ret,
                size_t *ret_size) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *message = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        _cleanup_free_ char *formatted = NULL;
        int r;

        assert(result);
        assert(ret);

        r = verify_result_build_parameters(result, &parameters);
        if (r < 0)
                return r;

        r = sd_json_buildo(&message, SD_JSON_BUILD_PAIR_VARIANT("parameters", parameters));
        if (r < 0)
                return r;

        r = sd_json_variant_format(message, /* flags= */ 0, &formatted);
        if (r < 0)
                return r;

        /* Include the trailing NUL used as the Varlink framing delimiter. */
        size_t size = (size_t) r + 1;
        if (size > size_max)
                return -E2BIG;

        if (ret_size)
                *ret_size = size;

        *ret = TAKE_PTR(parameters);
        return 0;
}

static int vl_method_verify(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "unitFiles", SD_JSON_VARIANT_ARRAY, json_dispatch_strv_path,
                  offsetof(VerifyParameters, unit_files), SD_JSON_NULLABLE|SD_JSON_STRICT },
                {}
        };
        static const VerifyUnitsLimits limits = {
                .input_filenames_max = VERIFY_INPUT_FILENAMES_MAX,
                .input_filename_bytes_max = VERIFY_INPUT_FILENAME_BYTES_MAX,
                .unit_name_map_max = VERIFY_UNIT_NAME_MAP_MAX,
                .diagnostics_max = VERIFY_DIAGNOSTICS_MAX,
                .diagnostic_bytes_max = VERIFY_DIAGNOSTIC_BYTES_MAX,
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        _cleanup_(verify_parameters_done) VerifyParameters p = {};
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        RuntimeScope runtime_scope;
        int r;

        assert(link);
        assert(parameters);
        assert(userdata);

        runtime_scope = *(RuntimeScope*) userdata;
        assert(IN_SET(runtime_scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        const VerifyUnitsParameters verify_parameters = {
                .filenames = p.unit_files,
                .runtime_scope = runtime_scope,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .suppress_output = true,
                .limits = limits,
        };

        r = verify_units(&verify_parameters, &result);
        if (r < 0)
                return r;

        r = verify_result_build_varlink_reply(
                        &result,
                        VERIFY_REPLY_BYTES_MAX,
                        &reply,
                        /* ret_size= */ NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, reply);
}

int verify_varlink_server(RuntimeScope runtime_scope) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        int r;

        assert(IN_SET(runtime_scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));

        r = varlink_server_new(
                        &server,
                        SD_VARLINK_SERVER_ROOT_ONLY |
                                SD_VARLINK_SERVER_MYSELF_ONLY |
                                SD_VARLINK_SERVER_INHERIT_USERDATA,
                        &runtime_scope);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_Analyze);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(server, "io.systemd.Analyze.Verify", vl_method_verify);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}
