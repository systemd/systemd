/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "analyze-verify-util.h"
#include "runtime-scope.h"

int verify_result_build_varlink_reply(
                const VerifyUnitsResult *result,
                size_t size_max,
                sd_json_variant **ret,
                size_t *ret_size);
int verify_varlink_server(RuntimeScope runtime_scope);
