/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-protocol.h"
#include "dhcp-relay-internal.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "prioq.h"

static sd_dhcp_relay* dhcp_relay_free(sd_dhcp_relay *relay) {
        if (!relay)
                return NULL;

        assert(hashmap_isempty(relay->interfaces));
        hashmap_free(relay->interfaces);
        assert(hashmap_isempty(relay->downstream_interfaces));
        hashmap_free(relay->downstream_interfaces);
        assert(prioq_isempty(relay->upstream_interfaces));
        prioq_free(relay->upstream_interfaces);

        sd_event_unref(relay->event);

        iovec_done(&relay->remote_id);
        tlv_unref(relay->extra_options);
        return mfree(relay);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_relay, sd_dhcp_relay, dhcp_relay_free);

int sd_dhcp_relay_new(sd_dhcp_relay **ret) {
        assert_return(ret, -EINVAL);

        sd_dhcp_relay *relay = new(sd_dhcp_relay, 1);
        if (!relay)
                return -ENOMEM;

        *relay = (sd_dhcp_relay) {
                .n_ref = 1,
                .server_port = DHCP_PORT_SERVER,
        };

        *ret = TAKE_PTR(relay);
        return 0;
}

int sd_dhcp_relay_attach_event(sd_dhcp_relay *relay, sd_event *event, int64_t priority) {
        int r;

        assert_return(relay, -EINVAL);
        assert_return(!relay->event, -EBUSY);

        if (event)
                relay->event = sd_event_ref(event);
        else {
                r = sd_event_default(&relay->event);
                if (r < 0)
                        return r;
        }

        relay->event_priority = priority;
        return 0;
}

int sd_dhcp_relay_detach_event(sd_dhcp_relay *relay) {
        assert_return(relay, -EINVAL);

        relay->event = sd_event_unref(relay->event);
        return 0;
}

sd_event* sd_dhcp_relay_get_event(sd_dhcp_relay *relay) {
        assert_return(relay, NULL);

        return relay->event;
}

int sd_dhcp_relay_set_server_address(sd_dhcp_relay *relay, const struct in_addr *address) {
        assert_return(relay, -EINVAL);
        assert_return(address, -EINVAL);

        relay->server_address = *address;
        return 0;
}

int sd_dhcp_relay_get_server_address(sd_dhcp_relay *relay, struct in_addr *ret) {
        assert_return(relay, -EINVAL);

        if (ret)
                *ret = relay->server_address;

        return in4_addr_is_set(&relay->server_address);
}

int sd_dhcp_relay_set_server_port(sd_dhcp_relay *relay, uint16_t port) {
        assert_return(relay, -EINVAL);

        relay->server_port = port;
        return 0;
}

int sd_dhcp_relay_set_remote_id(sd_dhcp_relay *relay, const struct iovec *iov) {
        assert_return(relay, -EINVAL);

        return iovec_done_and_memdup(&relay->remote_id, iov);
}

int sd_dhcp_relay_set_server_identifier_override(sd_dhcp_relay *relay, int b) {
        assert_return(relay, -EINVAL);

        relay->server_identifier_override = b;
        return 0;
}

int dhcp_relay_set_extra_options(sd_dhcp_relay *relay, TLV *options) {
        assert(relay);

        return unref_and_replace_full(relay->extra_options, options, tlv_ref, tlv_unref);
}
