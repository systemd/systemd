/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-directory-util.h"
#include "string-table.h"

/* This table maps ExecDirectoryType to the setting it is configured with in the unit */
static const char* const exec_directory_type_table[_EXEC_DIRECTORY_TYPE_MAX] = {
        [EXEC_DIRECTORY_RUNTIME]       = "RuntimeDirectory",
        [EXEC_DIRECTORY_STATE]         = "StateDirectory",
        [EXEC_DIRECTORY_CACHE]         = "CacheDirectory",
        [EXEC_DIRECTORY_LOGS]          = "LogsDirectory",
        [EXEC_DIRECTORY_CONFIGURATION] = "ConfigurationDirectory",
};

DEFINE_STRING_TABLE_LOOKUP(exec_directory_type, ExecDirectoryType);
