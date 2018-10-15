/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netlink-internal.h"
#include "netlink-slot.h"
#include "string-util.h"

int netlink_slot_allocate(
                sd_netlink *nl,
                bool floating,
                NetlinkSlotType type,
                size_t extra,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                const char *description,
                sd_netlink_slot **ret) {

        _cleanup_free_ sd_netlink_slot *slot = NULL;

        assert(nl);
        assert(ret);

        slot = malloc0(offsetof(sd_netlink_slot, reply_callback) + extra);
        if (!slot)
                return -ENOMEM;

        slot->n_ref = 1;
        slot->netlink = nl;
        slot->userdata = userdata;
        slot->destroy_callback = destroy_callback;
        slot->type = type;
        slot->floating = floating;

        if (description) {
                slot->description = strdup(description);
                if (!slot->description)
                        return -ENOMEM;
        }

        if (!floating)
                sd_netlink_ref(nl);

        LIST_PREPEND(slots, nl->slots, slot);

        *ret = TAKE_PTR(slot);

        return 0;
}

void netlink_slot_disconnect(sd_netlink_slot *slot, bool unref) {
        sd_netlink *nl;

        assert(slot);

        nl = slot->netlink;
        if (!nl)
                return;

        switch (slot->type) {

        case NETLINK_REPLY_CALLBACK:
                (void) hashmap_remove(nl->reply_callbacks, &slot->reply_callback.serial);

                if (slot->reply_callback.timeout != 0)
                        prioq_remove(nl->reply_callbacks_prioq, &slot->reply_callback, &slot->reply_callback.prioq_idx);

                break;
        case NETLINK_MATCH_CALLBACK:
                LIST_REMOVE(match_callbacks, nl->match_callbacks, &slot->match_callback);

                switch (slot->match_callback.type) {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                        (void) socket_broadcast_group_unref(nl, RTNLGRP_LINK);

                        break;
                case RTM_NEWADDR:
                case RTM_DELADDR:
                        (void) socket_broadcast_group_unref(nl, RTNLGRP_IPV4_IFADDR);
                        (void) socket_broadcast_group_unref(nl, RTNLGRP_IPV6_IFADDR);

                        break;
                case RTM_NEWROUTE:
                case RTM_DELROUTE:
                        (void) socket_broadcast_group_unref(nl, RTNLGRP_IPV4_ROUTE);
                        (void) socket_broadcast_group_unref(nl, RTNLGRP_IPV6_ROUTE);

                        break;
                }

                break;
        default:
                assert_not_reached("Wut? Unknown slot type?");
        }

        slot->type = _NETLINK_SLOT_INVALID;
        slot->netlink = NULL;
        LIST_REMOVE(slots, nl->slots, slot);

        if (!slot->floating)
                sd_netlink_unref(nl);
        else if (unref)
                sd_netlink_slot_unref(slot);
}

static sd_netlink_slot* netlink_slot_free(sd_netlink_slot *slot) {
        assert(slot);

        netlink_slot_disconnect(slot, false);

        if (slot->destroy_callback)
                slot->destroy_callback(slot->userdata);

        free(slot->description);
        return mfree(slot);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_netlink_slot, sd_netlink_slot, netlink_slot_free);

sd_netlink *sd_netlink_slot_get_netlink(sd_netlink_slot *slot) {
        assert_return(slot, NULL);

        return slot->netlink;
}

void *sd_netlink_slot_get_userdata(sd_netlink_slot *slot) {
        assert_return(slot, NULL);

        return slot->userdata;
}

void *sd_netlink_slot_set_userdata(sd_netlink_slot *slot, void *userdata) {
        void *ret;

        assert_return(slot, NULL);

        ret = slot->userdata;
        slot->userdata = userdata;

        return ret;
}

int sd_netlink_slot_get_destroy_callback(sd_netlink_slot *slot, sd_netlink_destroy_t *callback) {
        assert_return(slot, -EINVAL);

        if (callback)
                *callback = slot->destroy_callback;

        return !!slot->destroy_callback;
}

int sd_netlink_slot_set_destroy_callback(sd_netlink_slot *slot, sd_netlink_destroy_t callback) {
        assert_return(slot, -EINVAL);

        slot->destroy_callback = callback;
        return 0;
}

int sd_netlink_slot_get_floating(sd_netlink_slot *slot) {
        assert_return(slot, -EINVAL);

        return slot->floating;
}

int sd_netlink_slot_set_floating(sd_netlink_slot *slot, int b) {
        assert_return(slot, -EINVAL);

        if (slot->floating == !!b)
                return 0;

        if (!slot->netlink) /* Already disconnected */
                return -ESTALE;

        slot->floating = b;

        if (b) {
                sd_netlink_slot_ref(slot);
                sd_netlink_unref(slot->netlink);
        } else {
                sd_netlink_ref(slot->netlink);
                sd_netlink_slot_unref(slot);
        }

        return 1;
}

int sd_netlink_slot_get_description(sd_netlink_slot *slot, const char **description) {
        assert_return(slot, -EINVAL);

        if (description)
                *description = slot->description;

        return !!slot->description;
}

int sd_netlink_slot_set_description(sd_netlink_slot *slot, const char *description) {
        assert_return(slot, -EINVAL);

        return free_and_strdup(&slot->description, description);
}
