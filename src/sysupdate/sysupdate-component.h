/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

/* Metadata describing a component, as read from a sysupdate.<component>.component file */
typedef struct Component {
        char *description;
        char **documentation;

        bool enabled;

        int suggest;
        Condition *suggest_on;

        char *min_version;
        char *max_version;
        char **protected_versions;
} Component;

#define COMPONENT_NULL                          \
        (Component) {                           \
                .enabled = true,                \
                .suggest = -1,                  \
        }

void component_done(Component *c);

int component_read_definition(Component *c, const char *name, const char *root);

int component_is_suggested(const Component *c);
