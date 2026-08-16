/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "analyze-verify-util.h"
#include "analyze-verify-varlink.h"
#include "hashmap.h"
#include "install.h"
#include "json-util.h"
#include "log.h"
#include "path-lookup.h"
#include "path-util.h"
#include "runtime-scope.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "varlink-io.systemd.Analyze.h"
#include "varlink-util.h"

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

int verify_result_build_varlink_reply(
                const VerifyUnitsResult *result,
                sd_json_variant **ret) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(result);
        assert(ret);

        FOREACH_ARRAY(diagnostic, result->diagnostics, result->n_diagnostics) {
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

static bool unit_file_is_selected(const UnitFileList *unit_file) {
        assert(unit_file);

        return !IN_SET(unit_file->state, UNIT_FILE_ALIAS, UNIT_FILE_MASKED, UNIT_FILE_MASKED_RUNTIME);
}

static int instance_candidate(size_t n, size_t length_max, char **ret) {
        static const char alphabet[] = ALPHANUMERICAL ":-_.\\@";
        _cleanup_free_ char *instance = NULL;
        size_t encoded;

        assert(ret);

        if (!ADD_SAFE(&encoded, n, 1))
                return -E2BIG;

        size_t length = 0;
        for (size_t k = encoded; k > 0; k = (k - 1) / (ELEMENTSOF(alphabet) - 1))
                length++;

        if (length > length_max)
                return -E2BIG;

        instance = new(char, length + 1);
        if (!instance)
                return -ENOMEM;

        size_t k = encoded;
        for (size_t i = length; i > 0; i--) {
                k--;
                instance[i - 1] = alphabet[k % (ELEMENTSOF(alphabet) - 1)];
                k /= ELEMENTSOF(alphabet) - 1;
        }
        instance[length] = 0;

        *ret = TAKE_PTR(instance);
        return 0;
}

static int instantiate_template_path(
                Hashmap *unit_files,
                const char *name,
                const char *path,
                char **ret) {

        size_t instance_length_max;
        int r;

        assert(unit_files);
        assert(unit_name_is_valid(name, UNIT_NAME_TEMPLATE));
        assert(path);
        assert(ret);

        instance_length_max = UNIT_NAME_MAX - 1 - strlen(name);

        for (size_t n = 0;; n++) {
                _cleanup_free_ char *candidate = NULL, *directory = NULL, *instantiated = NULL;

                r = instance_candidate(n, instance_length_max, &candidate);
                if (r == -E2BIG)
                        break;
                if (r < 0)
                        return r;

                r = unit_name_replace_instance(name, candidate, &instantiated);
                if (r < 0)
                        return r;
                if (hashmap_contains(unit_files, instantiated))
                        continue;

                r = path_extract_directory(path, &directory);
                if (r < 0)
                        return r;

                *ret = path_join(directory, instantiated);
                return *ret ? 0 : -ENOMEM;
        }

        /* Keep an uninstantiable template so the ordinary verifier reports it and continues. */
        return strdup_to(ret, path);
}

int verify_varlink_collect_unit_files(
                RuntimeScope runtime_scope,
                const char *root,
                char ***ret_paths,
                char ***ret_lookup_path) {

        _cleanup_(lookup_paths_done) LookupPaths lookup_paths = {};
        _cleanup_hashmap_free_ Hashmap *unit_files = NULL;
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        assert(IN_SET(runtime_scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));
        assert(ret_paths);
        assert(ret_lookup_path);

        r = lookup_paths_init(&lookup_paths, runtime_scope, /* flags= */ 0, root);
        if (r < 0)
                return r;

        r = unit_file_get_list(
                        runtime_scope,
                        root,
                        /* states= */ NULL,
                        /* patterns= */ NULL,
                        &unit_files);
        if (r < 0)
                return r;

        /* Preserve lookup-path order and make diagnostic order within each directory deterministic. */
        STRV_FOREACH(directory, lookup_paths.search_path) {
                _cleanup_strv_free_ char **directory_paths = NULL;
                const char *name;
                UnitFileList *unit_file;

                HASHMAP_FOREACH_KEY(unit_file, name, unit_files) {
                        _cleanup_free_ char *path = NULL;

                        if (!unit_file_is_selected(unit_file))
                                continue;

                        const char *relative = path_startswith(unit_file->path, *directory);
                        if (!relative || strchr(relative, '/'))
                                continue;

                        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE))
                                r = instantiate_template_path(unit_files, name, unit_file->path, &path);
                        else
                                r = strdup_to(&path, unit_file->path);
                        if (r < 0)
                                return r;

                        r = strv_consume(&directory_paths, TAKE_PTR(path));
                        if (r < 0)
                                return r;
                }

                strv_sort(directory_paths);
                r = strv_extend_strv(&paths, directory_paths, /* filter_duplicates= */ false);
                if (r < 0)
                        return r;
        }

        *ret_paths = TAKE_PTR(paths);
        *ret_lookup_path = TAKE_PTR(lookup_paths.search_path);
        return 0;
}

static int vl_method_verify(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "unitFiles", SD_JSON_VARIANT_ARRAY, json_dispatch_strv_path, 0,
                  SD_JSON_NULLABLE|SD_JSON_STRICT },
                {}
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        _cleanup_(verify_units_result_done) VerifyUnitsResult result = {};
        _cleanup_strv_free_ char **unit_files = NULL, **lookup_path_override = NULL;
        RuntimeScope runtime_scope;
        int r;

        assert(link);
        assert(parameters);
        assert(userdata);

        runtime_scope = *(RuntimeScope*) userdata;
        assert(IN_SET(runtime_scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &unit_files);
        if (r != 0)
                return r;

        if (strv_isempty(unit_files)) {
                unit_files = strv_free(unit_files);

                r = verify_varlink_collect_unit_files(
                                runtime_scope,
                                /* root= */ NULL,
                                &unit_files,
                                &lookup_path_override);
                if (r < 0)
                        return r;
        }

        const VerifyUnitsParameters verify_parameters = {
                .filenames = unit_files,
                .runtime_scope = runtime_scope,
                .recursive_errors = RECURSIVE_ERRORS_YES,
                .instance = "test_instance",
                .lookup_path_override = lookup_path_override,
                .suppress_output = true,
        };

        r = verify_units(&verify_parameters, &result);
        if (r < 0)
                return r;

        r = verify_result_build_varlink_reply(&result, &reply);
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
