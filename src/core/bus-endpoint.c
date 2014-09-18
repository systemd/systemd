/***
  This file is part of systemd.

  Copyright 2014 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>

#include "bus-endpoint.h"

int bus_endpoint_new(BusEndpoint **ep)
{
        assert(ep);

        *ep = new0(BusEndpoint, 1);
        if (!*ep)
                return -ENOMEM;

        return 0;
}

int bus_endpoint_add_policy(BusEndpoint *ep, const char *name, BusPolicyAccess access)
{
        _cleanup_free_ BusEndpointPolicy *po = NULL;
        _cleanup_free_ char *key = NULL;
        int r;

        assert(ep);
        assert(name);
        assert(access > _BUS_POLICY_ACCESS_INVALID && access < _BUS_POLICY_ACCESS_MAX);

        /* check if we already have this name in the policy list. If we do, see if the new access level
         * is higher than the exising one, and upgrade the entry in that case. Otherwise, do nothing.
         */

        if (ep->policy_hash) {
                po = hashmap_get(ep->policy_hash, name);
                if (po) {
                        if (po->access < access)
                                po->access = access;

                        return 0;
                }
        } else {
                ep->policy_hash = hashmap_new(&string_hash_ops);
                if (!ep->policy_hash)
                        return -ENOMEM;
        }

        po = new0(BusEndpointPolicy, 1);
        if (!po)
                return -ENOMEM;

        key = strdup(name);
        if (!key)
                return -ENOMEM;

        po->name = key;
        po->access = access;

        r = hashmap_put(ep->policy_hash, key, po);
        if (r < 0)
                return r;

        po = NULL;
        key = NULL;
        return 0;
}

void bus_endpoint_free(BusEndpoint *endpoint)
{
        if (!endpoint)
                return;

        hashmap_free_free_free(endpoint->policy_hash);
        free(endpoint);
}
