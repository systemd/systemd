/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "forward.h"

typedef enum ComponentSuccessAction {
        COMPONENT_SUCCESS_CONTINUE,  /* Continue with the next component */
        COMPONENT_SUCCESS_RESTART,   /* Finish the current iteration, and start the next one */
        _COMPONENT_SUCCESS_ACTION_MAX,
        _COMPONENT_SUCCESS_ACTION_INVALID = -EINVAL,
} ComponentSuccessAction;

CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers);
CONFIG_PARSER_PROTOTYPE(config_parse_url_specifiers_many);
CONFIG_PARSER_PROTOTYPE(config_parse_condition);
CONFIG_PARSER_PROTOTYPE(config_parse_component_success_action);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(suggest_on_type, ConditionType);
