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

#include "alloc-util.h"
#include "bus-endpoint.h"
#include "bus-kernel.h"
#include "bus-policy.h"
#include "kdbus.h"

int bus_kernel_set_endpoint_policy(int fd, uid_t uid, BusEndpoint *ep) {

        struct kdbus_cmd *update;
        struct kdbus_item *n;
        BusEndpointPolicy *po;
        Iterator i;
        size_t size;
        int r;

        size = ALIGN8(offsetof(struct kdbus_cmd, items));

        HASHMAP_FOREACH(po, ep->policy_hash, i) {
                size += ALIGN8(offsetof(struct kdbus_item, str) + strlen(po->name) + 1);
                size += ALIGN8(offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access));
        }

        update = alloca0_align(size, 8);
        update->size = size;

        n = update->items;

        HASHMAP_FOREACH(po, ep->policy_hash, i) {
                n->type = KDBUS_ITEM_NAME;
                n->size = offsetof(struct kdbus_item, str) + strlen(po->name) + 1;
                strcpy(n->str, po->name);
                n = KDBUS_ITEM_NEXT(n);

                n->type = KDBUS_ITEM_POLICY_ACCESS;
                n->size = offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access);

                n->policy_access.type = KDBUS_POLICY_ACCESS_USER;
                n->policy_access.access = bus_kernel_translate_access(po->access);
                n->policy_access.id = uid;

                n = KDBUS_ITEM_NEXT(n);
        }

        r = ioctl(fd, KDBUS_CMD_ENDPOINT_UPDATE, update);
        if (r < 0)
                return -errno;

        return 0;
}

int bus_endpoint_new(BusEndpoint **ep) {
        assert(ep);

        *ep = new0(BusEndpoint, 1);
        if (!*ep)
                return -ENOMEM;

        return 0;
}

int bus_endpoint_add_policy(BusEndpoint *ep, const char *name, BusPolicyAccess access) {
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

void bus_endpoint_free(BusEndpoint *endpoint) {
        if (!endpoint)
                return;

        hashmap_free_free_free(endpoint->policy_hash);
        free(endpoint);
}
