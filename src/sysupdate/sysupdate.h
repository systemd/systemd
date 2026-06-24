/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"
#include "sysupdate-target.h"

typedef struct Context {
        /* Parameters/Command line arguments: */
        char *definitions;
        bool sync;
        uint64_t instances_max;
        char *root;
        char *image;
        bool reboot;
        int cleanup;
        char *component;
        bool component_all;
        int verify;
        ImagePolicy *image_policy;
        bool offline;
        char *transfer_source;

        /* Loaded state: */
        LoopDevice *loop_device;
        char *mounted_dir;

        char *component_description;
        char **component_documentation;
        bool component_enabled;

        int component_suggest;
        Condition *component_suggest_on;

        Transfer **transfers;
        size_t n_transfers;

        Transfer **disabled_transfers;
        size_t n_disabled_transfers;

        Hashmap *features; /* Defined features, keyed by ID */

        UpdateSet **update_sets;
        size_t n_update_sets;

        UpdateSet *newest_installed, *candidate;

        Hashmap *web_cache; /* Cache for downloaded resources, keyed by URL */

        int installdb_fd;

        TargetIdentifier target_identifier;
} Context;

void context_done(Context *c);
