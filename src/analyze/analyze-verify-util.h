/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "runtime-scope.h"

typedef struct ExecCommand ExecCommand;
typedef struct Manager Manager;
typedef struct Unit Unit;

typedef struct VerifyDiagnostic {
        int priority;
        char *message;
        char *unit;
        char *configuration_file;
        unsigned configuration_line;
        char *message_id;
} VerifyDiagnostic;

typedef struct VerifyDiagnostics {
        VerifyDiagnostic *items;
        size_t n_items;

        /* Includes each VerifyDiagnostic plus every owned string and its terminating NUL. */
        size_t n_bytes;
        size_t items_max;
        size_t bytes_max;
} VerifyDiagnostics;

typedef enum RecursiveErrors {
        RECURSIVE_ERRORS_YES,               /* Look for errors in all associated units */
        RECURSIVE_ERRORS_NO,                /* Don't look for errors in any but the selected unit */
        RECURSIVE_ERRORS_ONE,               /* Look for errors in the selected unit and its direct
                                             * dependencies */
        _RECURSIVE_ERRORS_MAX,
        _RECURSIVE_ERRORS_INVALID = -EINVAL,
} RecursiveErrors;

typedef struct VerifyUnitsLimits {
        /* All limits use zero to mean unlimited. */
        size_t input_filenames_max;
        /* Includes the terminating NUL of every input filename. */
        size_t input_filename_bytes_max;
        /* Independently bounds each retained name-map collection and the selected unit names. */
        size_t unit_name_map_max;
        size_t diagnostics_max;
        size_t diagnostic_bytes_max;
} VerifyUnitsLimits;

typedef struct VerifyUnitsParameters {
        /* NULL or an empty list selects every effective unit in the manager's lookup path. */
        char * const *filenames;
        RuntimeScope runtime_scope;
        RecursiveErrors recursive_errors;
        const char *root;
        const char *instance;
        bool check_man;
        bool run_unit_generators;
        bool run_environment_generators;
        bool suppress_output;
        VerifyUnitsLimits limits;
} VerifyUnitsParameters;

typedef struct VerifyUnitsResult {
        VerifyDiagnostics diagnostics;

        /* A negative value means verification completed and found a problem. This is kept separate
         * from verify_units()'s return value to preserve the legacy CLI exit status. */
        int legacy_status;
} VerifyUnitsResult;

int verify_build_unit_path(char * const *filenames, char **ret);
int verify_check_input_filenames(
                char * const *filenames,
                const VerifyUnitsLimits *limits,
                size_t *ret_n_filenames);
int verify_discover_unit_names(
                Manager *manager,
                const char *preferred_instance,
                size_t max_names,
                char ***ret);
int verify_prepare_filename(const char *filename, const char *instance, char **ret);
void verify_diagnostic_done(VerifyDiagnostic *diagnostic);
void verify_diagnostics_done(VerifyDiagnostics *diagnostics);
void verify_units_result_done(VerifyUnitsResult *result);
int verify_diagnostics_add_log_record(VerifyDiagnostics *diagnostics, const LogRecord *record);
int verify_executable(Unit *u, const ExecCommand *exec, const char *root);

/* Returns a negative error when verification could not be completed, without updating ret. A completed
 * verification returns zero; findings are reported through ret independently of the ambient log level,
 * which only controls their presentation. NULL or empty filenames scan the effective lookup path. */
int verify_units(const VerifyUnitsParameters *parameters, VerifyUnitsResult *ret);

DECLARE_STRING_TABLE_LOOKUP(recursive_errors, RecursiveErrors);
