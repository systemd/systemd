/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

/* A component as announced by a component provider via io.systemd.SysUpdate.Provider.ListTargets() */
typedef struct ProviderComponent {
        char *name;
        char *provider;             /* The socket name of the provider, relative to VARLINK_DIR_SYSUPDATE_PROVIDER */
        sd_json_variant *target;    /* The raw Target object, carrying the component's metadata, see component_from_json() */
} ProviderComponent;

ProviderComponent* provider_component_free(ProviderComponent *pc);
DEFINE_TRIVIAL_CLEANUP_FUNC(ProviderComponent*, provider_component_free);

extern const struct hash_ops provider_component_hash_ops;

int provider_list_components(Hashmap **ret);

int provider_describe_component(
                const char *name,
                char **ret_provider,
                sd_json_variant **ret_target,
                sd_json_variant **ret_features,
                sd_json_variant **ret_transfers);
