/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-network-json.h"
#include "networkd-network.h"

int network_build_json(Network *network, JsonVariant **ret) {
        assert(ret);

        if (!network) {
                *ret = NULL;
                return 0;
        }

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("NetworkFile", JSON_BUILD_STRING(network->filename))));
}
