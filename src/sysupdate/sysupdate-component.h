/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser-forward.h"
#include "sysupdate-forward.h"

typedef enum ComponentSuccessAction {
        COMPONENT_SUCCESS_CONTINUE,  /* Continue with the next component */
        COMPONENT_SUCCESS_RESTART,   /* Finish the current iteration, and start the next one */
        _COMPONENT_SUCCESS_ACTION_MAX,
        _COMPONENT_SUCCESS_ACTION_INVALID = -EINVAL,
} ComponentSuccessAction;

typedef enum ComponentFailureAction {
        COMPONENT_FAILURE_CONTINUE,  /* Continue with the next component, but fail at the very end */
        COMPONENT_FAILURE_FAIL,      /* Fail immediately */
        _COMPONENT_FAILURE_ACTION_MAX,
        _COMPONENT_FAILURE_ACTION_INVALID = -EINVAL,
} ComponentFailureAction;

/* Metadata describing a component, as read from a sysupdate.<component>.component file */
typedef struct Component {
        char *description;
        char **documentation;

        int enabled; /* tristate, unset means enabled */

        ComponentSuccessAction success_action;
        ComponentFailureAction failure_action;

        int suggest; /* tristate */
        Condition *suggest_on;

        char *min_version;
        char *max_version;
        char **protected_versions;
} Component;

#define COMPONENT_NULL                          \
        (Component) {                           \
                .enabled = -1,                  \
                .suggest = -1,                  \
        }

void component_done(Component *c);

int component_read_definition(Component *c, const char *name, const char *root); /* returns > 0 if a file was found */

int component_is_suggested(const Component *c);

CONFIG_PARSER_PROTOTYPE(config_parse_component_success_action);
CONFIG_PARSER_PROTOTYPE(config_parse_component_failure_action);

int component_to_json(const Component *c, sd_json_variant **ret);
int component_from_json(Component *c, sd_json_variant *v, const char *origin);
