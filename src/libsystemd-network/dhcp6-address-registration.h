/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>

#include "dhcp6-client-internal.h"
#include "forward.h"
#include "sparse-endian.h"
#include "time-util.h"

typedef struct DHCP6AddressRegistration DHCP6AddressRegistration;

struct DHCP6AddressRegistration {
        sd_dhcp6_client *client; /* weak */
        struct in6_addr address;
        usec_t lifetime_preferred_usec;
        usec_t lifetime_valid_usec;

        sd_event_source *retransmit_event;
        be32_t transaction_id;
        unsigned transmission_count;
        usec_t retransmit_time_usec;
        usec_t retransmit_deadline_usec;
        bool transaction_active;
        bool registration_attempted;
};

typedef struct DHCP6AddressRegistrationEngine {
        bool enabled;
        bool supported;
        Hashmap *registrations;

        int fd;
        sd_event_source *receive_event;

        usec_t initial_retransmission_time_usec;
        unsigned max_retransmissions;
} DHCP6AddressRegistrationEngine;

int dhcp6_address_registration_open_socket(int ifindex);
int dhcp6_address_registration_send(
                int fd,
                const struct in6_addr *source,
                int ifindex,
                const struct sockaddr_in6 *destination,
                const void *packet,
                size_t len);
int dhcp6_address_registration_receive(
                int fd,
                void **ret_packet,
                size_t *ret_len,
                struct sockaddr_in6 *ret_sender,
                struct in6_addr *ret_destination,
                int *ret_ifindex,
                bool *ret_truncated);
uint32_t dhcp6_address_registration_random_u32(void);
uint64_t dhcp6_address_registration_random_u64_range(uint64_t upper_bound);

int dhcp6_client_address_registration_discover(
                sd_dhcp6_client *client,
                uint8_t message_type,
                bool advertised);
void dhcp6_client_address_registration_done(sd_dhcp6_client *client);
int dhcp6_client_address_registration_attach_event(sd_dhcp6_client *client);
void dhcp6_client_address_registration_detach_event(sd_dhcp6_client *client);

int dhcp6_client_update_address_registration_at(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec,
                usec_t now_usec);

int dhcp6_client_address_registration_retransmit_at(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t now_usec);
int dhcp6_client_process_address_registration_reply_at(
                sd_dhcp6_client *client,
                const void *packet,
                size_t len,
                const struct sockaddr_in6 *sender,
                const struct in6_addr *destination,
                int ifindex,
                bool truncated,
                usec_t now_usec);
int dhcp6_client_receive_address_registration_reply(sd_dhcp6_client *client);

usec_t dhcp6_address_registration_initial_retransmission_time(usec_t irt_usec, uint64_t random);
usec_t dhcp6_address_registration_next_retransmission_time(usec_t previous_usec, uint64_t random);
