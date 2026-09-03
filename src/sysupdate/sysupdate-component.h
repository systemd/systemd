/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

/* Metadata describing a component, as read from a sysupdate.<component>.component file */
typedef struct Component {
        char *description;
        char **documentation;

        int enabled; /* tristate, unset means enabled */

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

int component_read_definition(Component *c, const char *name, const char *root);

int component_is_suggested(const Component *c);

int component_to_json(const Component *c, sd_json_variant **ret);
int component_from_json(Component *c, sd_json_variant *v, const char *origin);
