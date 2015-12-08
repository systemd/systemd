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
#include "bus-kernel.h"
#include "bus-policy.h"
#include "kdbus.h"
#include "string-table.h"
#include "user-util.h"
#include "util.h"

int bus_kernel_translate_access(BusPolicyAccess access) {
        assert(access >= 0);
        assert(access < _BUS_POLICY_ACCESS_MAX);

        switch (access) {

        case BUS_POLICY_ACCESS_SEE:
                return KDBUS_POLICY_SEE;

        case BUS_POLICY_ACCESS_TALK:
                return KDBUS_POLICY_TALK;

        case BUS_POLICY_ACCESS_OWN:
                return KDBUS_POLICY_OWN;

        default:
                assert_not_reached("Unknown policy access");
        }
}

int bus_kernel_translate_policy(const BusNamePolicy *policy, struct kdbus_item *item) {
        int r;

        assert(policy);
        assert(item);

        switch (policy->type) {

        case BUSNAME_POLICY_TYPE_USER: {
                const char *user = policy->name;
                uid_t uid;

                r = get_user_creds(&user, &uid, NULL, NULL, NULL);
                if (r < 0)
                        return r;

                item->policy_access.type = KDBUS_POLICY_ACCESS_USER;
                item->policy_access.id = uid;
                break;
        }

        case BUSNAME_POLICY_TYPE_GROUP: {
                const char *group = policy->name;
                gid_t gid;

                r = get_group_creds(&group, &gid);
                if (r < 0)
                        return r;

                item->policy_access.type = KDBUS_POLICY_ACCESS_GROUP;
                item->policy_access.id = gid;
                break;
        }

        default:
                assert_not_reached("Unknown policy type");
        }

        item->policy_access.access = bus_kernel_translate_access(policy->access);

        return 0;
}

int bus_kernel_make_starter(
                int fd,
                const char *name,
                bool activating,
                bool accept_fd,
                BusNamePolicy *policy,
                BusPolicyAccess world_policy) {

        struct kdbus_cmd_free cmd_free = { .size = sizeof(cmd_free) };
        struct kdbus_cmd_hello *hello;
        struct kdbus_item *n;
        size_t policy_cnt = 0;
        BusNamePolicy *po;
        size_t size;
        int r;

        assert(fd >= 0);
        assert(name);

        LIST_FOREACH(policy, po, policy)
                policy_cnt++;

        if (world_policy >= 0)
                policy_cnt++;

        size = offsetof(struct kdbus_cmd_hello, items) +
               ALIGN8(offsetof(struct kdbus_item, str) + strlen(name) + 1) +
               policy_cnt * ALIGN8(offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access));

        hello = alloca0_align(size, 8);

        n = hello->items;
        strcpy(n->str, name);
        n->size = offsetof(struct kdbus_item, str) + strlen(n->str) + 1;
        n->type = KDBUS_ITEM_NAME;
        n = KDBUS_ITEM_NEXT(n);

        LIST_FOREACH(policy, po, policy) {
                n->type = KDBUS_ITEM_POLICY_ACCESS;
                n->size = offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access);

                r = bus_kernel_translate_policy(po, n);
                if (r < 0)
                        return r;

                n = KDBUS_ITEM_NEXT(n);
        }

        if (world_policy >= 0) {
                n->type = KDBUS_ITEM_POLICY_ACCESS;
                n->size = offsetof(struct kdbus_item, policy_access) + sizeof(struct kdbus_policy_access);
                n->policy_access.type = KDBUS_POLICY_ACCESS_WORLD;
                n->policy_access.access = bus_kernel_translate_access(world_policy);
        }

        hello->size = size;
        hello->flags =
                (activating ? KDBUS_HELLO_ACTIVATOR : KDBUS_HELLO_POLICY_HOLDER) |
                (accept_fd ? KDBUS_HELLO_ACCEPT_FD : 0);
        hello->pool_size = KDBUS_POOL_SIZE;
        hello->attach_flags_send = _KDBUS_ATTACH_ANY;
        hello->attach_flags_recv = _KDBUS_ATTACH_ANY;

        if (ioctl(fd, KDBUS_CMD_HELLO, hello) < 0) {
                if (errno == ENOTTY) /* Major API change */
                        return -ESOCKTNOSUPPORT;
                return -errno;
        }

        /* not interested in any output values */
        cmd_free.offset = hello->offset;
        (void) ioctl(fd, KDBUS_CMD_FREE, &cmd_free);

        /* The higher 32bit of the bus_flags fields are considered
         * 'incompatible flags'. Refuse them all for now. */
        if (hello->bus_flags > 0xFFFFFFFFULL)
                return -ESOCKTNOSUPPORT;

        return fd;
}

static const char* const bus_policy_access_table[_BUS_POLICY_ACCESS_MAX] = {
        [BUS_POLICY_ACCESS_SEE] = "see",
        [BUS_POLICY_ACCESS_TALK] = "talk",
        [BUS_POLICY_ACCESS_OWN] = "own",
};

DEFINE_STRING_TABLE_LOOKUP(bus_policy_access, BusPolicyAccess);
