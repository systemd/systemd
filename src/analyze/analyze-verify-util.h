/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "runtime-scope.h"

typedef struct ExecCommand ExecCommand;
typedef struct Unit Unit;

typedef struct VerifyDiagnostic {
        int priority;
        char *message;
        char *unit;
        char *configuration_file;
        unsigned configuration_line;
        char *message_id;
} VerifyDiagnostic;

typedef enum RecursiveErrors {
        RECURSIVE_ERRORS_YES,               /* Look for errors in all associated units */
        RECURSIVE_ERRORS_NO,                /* Don't look for errors in any but the selected unit */
        RECURSIVE_ERRORS_ONE,               /* Look for errors in the selected unit and its direct
                                             * dependencies */
        _RECURSIVE_ERRORS_MAX,
        _RECURSIVE_ERRORS_INVALID = -EINVAL,
} RecursiveErrors;

typedef struct VerifyUnitsParameters {
        /* NULL or an empty list is a successful no-op; adapters may expand it before calling. */
        char * const *filenames;
        RuntimeScope runtime_scope;
        RecursiveErrors recursive_errors;
        const char *root;
        const char *instance;
        /* Borrowed complete search path to install instead of deriving one from filenames. */
        char * const *lookup_path_override;
        bool check_man;
        bool run_unit_generators;
        bool run_environment_generators;
        bool suppress_output;
} VerifyUnitsParameters;

typedef struct VerifyUnitsResult {
        VerifyDiagnostic *diagnostics;
        size_t n_diagnostics;

        /* A negative value means verification completed and found a problem. This is kept separate
         * from verify_units()'s return value to preserve the legacy CLI exit status. */
        int legacy_status;
} VerifyUnitsResult;

int verify_set_unit_path(char * const *filenames);
int verify_prepare_filename(const char *filename, const char *instance, char **ret);
void verify_units_result_done(VerifyUnitsResult *result);
int verify_executable(Unit *u, const ExecCommand *exec, const char *root);

/* Returns a negative error when verification could not be completed, without updating ret. A completed
 * verification returns zero; findings are reported through ret independently of the ambient log level,
 * which only controls their presentation. NULL or empty filenames are a successful no-op. */
int verify_units(const VerifyUnitsParameters *parameters, VerifyUnitsResult *ret);

DECLARE_STRING_TABLE_LOOKUP(recursive_errors, RecursiveErrors);
