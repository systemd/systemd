/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "set.h"

int routing_policy_rules_build_json(Set *rules, JsonVariant **ret);
