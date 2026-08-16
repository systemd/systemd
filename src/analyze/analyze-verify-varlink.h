/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "analyze-verify-util.h"
#include "runtime-scope.h"

int verify_result_build_varlink_reply(const VerifyUnitsResult *result, sd_json_variant **ret);
int verify_varlink_collect_unit_files(
                RuntimeScope runtime_scope,
                const char *root,
                char ***ret_paths,
                char ***ret_lookup_path);
int verify_varlink_server(RuntimeScope runtime_scope);
