/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp6-address-registration.h"
#include "dhcp6-internal.h"
#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "macro.h"

static int address_registration_receive_event(sd_event_source *s, int fd, uint32_t revents, void *userdata);
static int address_registration_retransmit_event(sd_event_source *s, uint64_t usec, void *userdata);

static DHCP6AddressRegistration *address_registration_free(DHCP6AddressRegistration *registration) {
        if (!registration)
                return NULL;

        sd_event_source_disable_unref(registration->retransmit_event);
        return mfree(registration);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                address_registration_hash_ops,
                struct in6_addr,
                in6_addr_hash_func,
                in6_addr_compare_func,
                DHCP6AddressRegistration,
                address_registration_free);

static void address_registration_cancel_transaction(DHCP6AddressRegistration *registration) {
        assert(registration);

        (void) event_source_disable(registration->retransmit_event);
        registration->transaction_active = false;
        registration->retransmit_deadline_usec = USEC_INFINITY;
}

static void address_registration_close_socket(sd_dhcp6_client *client) {
        DHCP6AddressRegistrationEngine *engine;

        assert(client);

        engine = &client->address_registration;
        engine->receive_event = sd_event_source_disable_unref(engine->receive_event);
        engine->fd = safe_close(engine->fd);
}

static int address_registration_attach_receive_event(sd_dhcp6_client *client) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *source = NULL;
        DHCP6AddressRegistrationEngine *engine;
        int r;

        assert(client);

        engine = &client->address_registration;
        if (!client->event || engine->fd < 0 || engine->receive_event)
                return 0;

        r = sd_event_add_io(
                        client->event,
                        &source,
                        engine->fd,
                        EPOLLIN,
                        address_registration_receive_event,
                        client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(source, client->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(source, "dhcp6-address-registration-receive");
        if (r < 0)
                return r;

        engine->receive_event = TAKE_PTR(source);
        return 0;
}

static int address_registration_ensure_socket(sd_dhcp6_client *client) {
        DHCP6AddressRegistrationEngine *engine;
        int r;

        assert(client);

        engine = &client->address_registration;
        if (engine->fd < 0) {
                assert(engine->enabled);
                assert(engine->supported);
                assert(client->ifindex > 0);

                r = dhcp6_address_registration_open_socket(client->ifindex);
                if (r < 0)
                        return r;

                engine->fd = r;
        }

        r = address_registration_attach_receive_event(client);
        if (r < 0)
                address_registration_close_socket(client);

        return r;
}

static int address_registration_send_message(DHCP6AddressRegistration *registration, usec_t now_usec) {
        _cleanup_free_ uint8_t *buf = NULL;
        sd_dhcp6_client *client;
        struct iaaddr iaaddr;
        struct sockaddr_in6 destination;
        DHCP6Message *message;
        size_t offset;
        int r;

        assert(registration);

        client = ASSERT_PTR(registration->client);
        assert(client->address_registration.enabled);
        assert(client->address_registration.supported);

        destination = (struct sockaddr_in6) {
                .sin6_family = AF_INET6,
                .sin6_addr = IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS,
                .sin6_port = htobe16(DHCP6_PORT_SERVER),
                .sin6_scope_id = client->ifindex,
        };

        usec_t valid_usec = usec_sub_unsigned(registration->lifetime_valid_usec, now_usec);
        if (valid_usec == 0)
                return -EADDRNOTAVAIL;

        r = address_registration_ensure_socket(client);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC0(buf, offsetof(DHCP6Message, options)))
                return -ENOMEM;

        message = (DHCP6Message*) buf;
        message->transaction_id = registration->transaction_id;
        message->type = DHCP6_MESSAGE_ADDR_REG_INFORM;
        offset = offsetof(DHCP6Message, options);

        assert(sd_dhcp_duid_is_set(&client->duid));
        r = dhcp6_option_append(
                        &buf,
                        &offset,
                        SD_DHCP6_OPTION_CLIENTID,
                        client->duid.size,
                        &client->duid.duid);
        if (r < 0)
                return r;

        iaaddr = (struct iaaddr) {
                .address = registration->address,
                .lifetime_preferred = usec_to_be32_sec(usec_sub_unsigned(
                                registration->lifetime_preferred_usec, now_usec)),
                .lifetime_valid = usec_to_be32_sec(valid_usec),
        };
        r = dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_IAADDR, sizeof(iaaddr), &iaaddr);
        if (r < 0)
                return r;

        r = dhcp6_address_registration_send(
                        client->address_registration.fd,
                        &registration->address,
                        client->ifindex,
                        &destination,
                        buf,
                        offset);
        if (r < 0) {
                address_registration_close_socket(client);
                return r;
        }

        log_dhcp6_client(client, "Sent Address Registration Inform for %s",
                         IN6_ADDR_TO_STRING(&registration->address));
        return 0;
}

usec_t dhcp6_address_registration_initial_retransmission_time(usec_t irt_usec, uint64_t random) {
        usec_t span;

        assert(irt_usec > 0);

        span = irt_usec / 5;
        assert(random <= span);

        return usec_add(usec_sub_unsigned(irt_usec, irt_usec / 10), random);
}

usec_t dhcp6_address_registration_next_retransmission_time(usec_t previous_usec, uint64_t random) {
        return usec_add(
                        previous_usec,
                        dhcp6_address_registration_initial_retransmission_time(previous_usec, random));
}

static usec_t address_registration_randomized_retransmission_time(
                usec_t base_usec,
                bool initial) {

        uint64_t random;

        random = dhcp6_address_registration_random_u64_range(base_usec / 5 + 1);
        return initial ?
                dhcp6_address_registration_initial_retransmission_time(base_usec, random) :
                dhcp6_address_registration_next_retransmission_time(base_usec, random);
}

static int address_registration_schedule_timer(
                DHCP6AddressRegistration *registration,
                usec_t deadline_usec) {

        sd_dhcp6_client *client;
        int r;

        assert(registration);

        client = ASSERT_PTR(registration->client);

        if (client->event && deadline_usec != USEC_INFINITY) {
                r = event_reset_time(
                                client->event,
                                &registration->retransmit_event,
                                CLOCK_BOOTTIME,
                                deadline_usec,
                                0,
                                address_registration_retransmit_event,
                                registration,
                                client->event_priority,
                                "dhcp6-address-registration-retransmit",
                                true);
                if (r < 0)
                        return r;
        }

        registration->retransmit_deadline_usec = deadline_usec;
        return 0;
}

static int address_registration_schedule_retransmission(
                DHCP6AddressRegistration *registration,
                usec_t now_usec) {

        assert(registration);

        usec_t deadline_usec = usec_add(now_usec, registration->retransmit_time_usec);

        if (deadline_usec == USEC_INFINITY)
                return -ERANGE;

        return address_registration_schedule_timer(registration, deadline_usec);
}

static int address_registration_transmit(
                DHCP6AddressRegistration *registration,
                usec_t now_usec,
                bool retransmission) {

        int r;

        assert(registration);

        if (retransmission)
                registration->retransmit_time_usec = address_registration_randomized_retransmission_time(
                                registration->retransmit_time_usec, /* initial= */ false);

        r = address_registration_schedule_retransmission(registration, now_usec);
        if (r < 0) {
                /* Nothing is left to drive the transaction once the retransmission timer is gone, so end it
                 * here rather than leave it active with no event source behind it. */
                address_registration_cancel_transaction(registration);
                return r;
        }

        registration->transmission_count++;

        r = address_registration_send_message(registration, now_usec);
        if (r >= 0)
                registration->registration_attempted = true;

        return r < 0 ? r : retransmission;
}

static int address_registration_start_transaction(
                DHCP6AddressRegistration *registration,
                usec_t now_usec) {

        sd_dhcp6_client *client;
        uint32_t transaction_id;

        assert(registration);

        client = ASSERT_PTR(registration->client);
        if (usec_sub_unsigned(registration->lifetime_valid_usec, now_usec) == 0)
                return -EADDRNOTAVAIL;

        address_registration_cancel_transaction(registration);

        transaction_id = dhcp6_address_registration_random_u32() & 0x00ffffffU;
        registration->transaction_id = htobe32(transaction_id);
        registration->transmission_count = 0;
        registration->retransmit_time_usec = address_registration_randomized_retransmission_time(
                        client->address_registration.initial_retransmission_time_usec,
                        /* initial= */ true);
        registration->transaction_active = true;

        return address_registration_transmit(registration, now_usec, /* retransmission= */ false);
}

int dhcp6_client_update_address_registration_at(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec,
                usec_t now_usec) {

        _cleanup_free_ DHCP6AddressRegistration *allocated = NULL;
        DHCP6AddressRegistration *registration;
        bool is_new = false;
        int r;

        assert(client);
        assert(address);

        if (usec_sub_unsigned(lifetime_valid_usec, now_usec) == 0) {
                dhcp6_client_remove_address_registration(client, address);
                return 0;
        }

        registration = hashmap_get(client->address_registration.registrations, address);
        if (!registration) {
                allocated = new(DHCP6AddressRegistration, 1);
                if (!allocated)
                        return -ENOMEM;

                *allocated = (DHCP6AddressRegistration) {
                        .client = client,
                        .address = *address,
                        .retransmit_deadline_usec = USEC_INFINITY,
                };

                r = hashmap_ensure_put(
                                &client->address_registration.registrations,
                                &address_registration_hash_ops,
                                &allocated->address,
                                allocated);
                if (r < 0)
                        return r;

                registration = allocated;
                is_new = true;
        }

        registration->lifetime_preferred_usec = lifetime_preferred_usec;
        registration->lifetime_valid_usec = lifetime_valid_usec;

        if (client->address_registration.supported &&
            !registration->registration_attempted &&
            !registration->transaction_active) {
                r = address_registration_start_transaction(registration, now_usec);
                if (r < 0) {
                        if (is_new)
                                TAKE_PTR(allocated);
                        return r;
                }
        }

        if (is_new)
                TAKE_PTR(allocated);

        return 1;
}

int dhcp6_client_update_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec) {

        return dhcp6_client_update_address_registration_at(
                        client,
                        address,
                        lifetime_preferred_usec,
                        lifetime_valid_usec,
                        now(CLOCK_BOOTTIME));
}

void dhcp6_client_remove_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address) {

        DHCP6AddressRegistration *registration;

        assert(client);
        assert(address);

        registration = hashmap_remove(client->address_registration.registrations, address);
        address_registration_free(registration);
}

int dhcp6_client_set_address_registration_enabled(sd_dhcp6_client *client, bool enabled) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp6_client_is_running(client), -EBUSY);

        client->address_registration.enabled = enabled;
        if (!enabled)
                dhcp6_client_address_registration_reset(client);

        return 0;
}

int dhcp6_client_address_registration_discover(
                sd_dhcp6_client *client,
                uint8_t message_type,
                bool advertised) {

        DHCP6AddressRegistration *registration;
        int r, ret = 1;

        assert(client);

        if (!IN_SET(message_type, DHCP6_MESSAGE_ADVERTISE, DHCP6_MESSAGE_REPLY))
                return 0;
        if (!client->address_registration.enabled || !advertised || client->address_registration.supported)
                return 0;

        client->address_registration.supported = true;

        HASHMAP_FOREACH(registration, client->address_registration.registrations) {
                r = address_registration_start_transaction(registration, now(CLOCK_BOOTTIME));
                if (r < 0)
                        ret = r;
        }

        return ret;
}

void dhcp6_client_address_registration_reset(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;

        assert(client);

        client->address_registration.supported = false;

        HASHMAP_FOREACH(registration, client->address_registration.registrations) {
                address_registration_cancel_transaction(registration);
                registration->registration_attempted = false;
        }

        address_registration_close_socket(client);
}

void dhcp6_client_address_registration_detach_event(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;

        assert(client);

        client->address_registration.receive_event =
                sd_event_source_disable_unref(client->address_registration.receive_event);

        HASHMAP_FOREACH(registration, client->address_registration.registrations)
                registration->retransmit_event =
                        sd_event_source_disable_unref(registration->retransmit_event);
}

int dhcp6_client_address_registration_attach_event(sd_dhcp6_client *client) {
        DHCP6AddressRegistration *registration;
        int r;

        assert(client);
        assert(client->event);

        r = address_registration_attach_receive_event(client);
        if (r < 0)
                goto fail;

        HASHMAP_FOREACH(registration, client->address_registration.registrations) {
                r = address_registration_schedule_timer(registration, registration->retransmit_deadline_usec);
                if (r < 0)
                        goto fail;
        }

        return 0;

fail:
        dhcp6_client_address_registration_detach_event(client);
        return r;
}

void dhcp6_client_address_registration_done(sd_dhcp6_client *client) {
        if (!client)
                return;

        dhcp6_client_address_registration_reset(client);

        client->address_registration.registrations =
                hashmap_free(client->address_registration.registrations);
}

int dhcp6_client_address_registration_retransmit_at(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t now_usec) {

        DHCP6AddressRegistration *registration;

        assert(client);
        assert(address);

        registration = hashmap_get(client->address_registration.registrations, address);
        if (!registration || !registration->transaction_active)
                return 0;

        if (usec_sub_unsigned(registration->lifetime_valid_usec, now_usec) == 0) {
                dhcp6_client_remove_address_registration(client, address);
                return 0;
        }

        if (client->address_registration.max_retransmissions > 0 &&
            registration->transmission_count >= client->address_registration.max_retransmissions) {
                address_registration_cancel_transaction(registration);
                return 0;
        }

        return address_registration_transmit(registration, now_usec, /* retransmission= */ true);
}

static void address_registration_log_transaction_error(
                DHCP6AddressRegistration *registration,
                int error,
                const char *operation) {

        assert(registration);
        assert(operation);

        log_dhcp6_client_errno(
                        registration->client,
                        error,
                        "Failed to %s address registration for %s%s: %m",
                        operation,
                        IN6_ADDR_TO_STRING(&registration->address),
                        registration->transaction_active ? ", retrying" : ", transaction stopped");
}

static int address_registration_retransmit_event(sd_event_source *s, uint64_t usec, void *userdata) {
        DHCP6AddressRegistration *registration = ASSERT_PTR(userdata);
        int r;

        r = dhcp6_client_address_registration_retransmit_at(
                        ASSERT_PTR(registration->client), &registration->address, now(CLOCK_BOOTTIME));
        if (r < 0)
                address_registration_log_transaction_error(registration, r, "retransmit");

        return 0;
}

int dhcp6_client_process_address_registration_reply_at(
                sd_dhcp6_client *client,
                const void *packet,
                size_t len,
                const struct sockaddr_in6 *sender,
                const struct in6_addr *destination,
                int ifindex,
                bool truncated,
                usec_t now_usec) {

        DHCP6AddressRegistration *registration;
        const DHCP6Message *message = packet;
        size_t offset = offsetof(DHCP6Message, options), n_iaaddr = 0;
        int r;

        assert(client);
        assert(packet || len == 0);
        assert(sender);
        assert(destination);

        if (truncated || len < sizeof(DHCP6Message))
                return 0;
        if (sender->sin6_port != htobe16(DHCP6_PORT_SERVER))
                return 0;

        if (ifindex != client->ifindex)
                return 0;

        registration = hashmap_get(client->address_registration.registrations, destination);
        if (!registration || !registration->transaction_active)
                return 0;
        if (usec_sub_unsigned(registration->lifetime_valid_usec, now_usec) == 0) {
                dhcp6_client_remove_address_registration(client, destination);
                return 0;
        }
        if (message->type != DHCP6_MESSAGE_ADDR_REG_REPLY ||
            (message->transaction_id & htobe32(0x00ffffffU)) != registration->transaction_id)
                return 0;

        while (offset < len) {
                const uint8_t *optval;
                size_t optlen;
                uint16_t optcode;

                r = dhcp6_option_parse(packet, len, &offset, &optcode, &optlen, &optval);
                if (r < 0)
                        return 0;

                if (optcode != SD_DHCP6_OPTION_IAADDR)
                        continue;

                if (++n_iaaddr > 1 || optlen != sizeof(struct iaaddr))
                        return 0;

                struct in6_addr address;
                memcpy(&address, optval, sizeof(address));
                if (!in6_addr_equal(&address, &registration->address))
                        return 0;
        }

        if (n_iaaddr != 1)
                return 0;

        address_registration_cancel_transaction(registration);
        log_dhcp6_client(client, "Received Address Registration Reply for %s",
                         IN6_ADDR_TO_STRING(&registration->address));
        return 1;
}

int dhcp6_client_receive_address_registration_reply(sd_dhcp6_client *client) {
        _cleanup_free_ void *packet = NULL;
        struct sockaddr_in6 sender;
        struct in6_addr destination;
        bool truncated;
        size_t len;
        int ifindex, r;

        assert(client);

        r = dhcp6_address_registration_receive(
                        client->address_registration.fd,
                        &packet,
                        &len,
                        &sender,
                        &destination,
                        &ifindex,
                        &truncated);
        if (ERRNO_IS_TRANSIENT(r) || ERRNO_IS_DISCONNECT(r))
                return 0;
        if (r < 0) {
                log_dhcp6_client_errno(client, r,
                                       "Failed to receive address registration reply, ignoring: %m");
                return 0;
        }

        r = dhcp6_client_process_address_registration_reply_at(
                        client,
                        packet,
                        len,
                        &sender,
                        &destination,
                        ifindex,
                        truncated,
                        now(CLOCK_BOOTTIME));
        if (r < 0)
                log_dhcp6_client_errno(client, r,
                                       "Failed to process address registration reply, ignoring: %m");

        return 0;
}

static int address_registration_receive_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp6_client *client = ASSERT_PTR(userdata);

        return dhcp6_client_receive_address_registration_reply(client);
}
