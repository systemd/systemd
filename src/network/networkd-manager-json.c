/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-link-json.h"
#include "networkd-manager-json.h"

int manager_build_json(Manager *manager, JsonVariant **ret) {
        return links_build_json(manager, ret);
}
