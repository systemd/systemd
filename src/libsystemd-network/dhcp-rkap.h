/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "sparse-endian.h"

/* The Reconfigure Key Authentication Protocol (RKAP) of DHCPv6 (RFC 9915 section 20.4) and the Forcerenew
 * Nonce Authentication protocol of DHCPv4 (RFC 6704 section 3.1.2), which is the same protocol carried in
 * the DHCPv4 Authentication option (RFC 3118). The server hands out a 128-bit key in its Reply (DHCPv6) or
 * DHCPACK (DHCPv4), and later authenticates its Reconfigure (DHCPv6) or DHCPFORCERENEW (DHCPv4) message with
 * an HMAC-MD5 over the whole message, computed with the digest field set to zero.
 *
 * Both use the same option body (after the option code and length, which differ between DHCPv4 and DHCPv6),
 * which is what the functions below operate on. */

#define DHCP_RKAP_PROTOCOL              3  /* RFC 3118: "Reconfigure Key", RFC 9915: RKAP */
#define DHCP_RKAP_ALGORITHM_HMAC_MD5    1
#define DHCP_RKAP_RDM_MONOTONIC         0  /* replay detection: monotonically increasing counter */

typedef enum DHCPRKAPType {
        DHCP_RKAP_TYPE_KEY              = 1, /* reconfigure key / forcerenew nonce, in Reply or DHCPACK */
        DHCP_RKAP_TYPE_HMAC_MD5         = 2, /* HMAC-MD5 digest, in Reconfigure or DHCPFORCERENEW */
} DHCPRKAPType;

#define DHCP_RKAP_KEY_SIZE              16

typedef struct DHCPRKAPAuth {
        uint8_t protocol;
        uint8_t algorithm;
        uint8_t rdm;
        be64_t replay;
        uint8_t type;
        uint8_t value[DHCP_RKAP_KEY_SIZE];
} _packed_ DHCPRKAPAuth;

typedef struct DHCPRKAPKey {
        bool set;
        uint8_t key[DHCP_RKAP_KEY_SIZE];
        uint64_t replay; /* the last replay detection value received from the server */
} DHCPRKAPKey;

void dhcp_rkap_key_clear(DHCPRKAPKey *key);

/* Takes the body of an Authentication option received in a Reply or DHCPACK, and if it carries a key,
 * stores it together with its replay detection value. Returns -EBADMSG for malformed options, -EOPNOTSUPP
 * for other authentication protocols or algorithms, and -ENOKEY if the option carries something else. */
int dhcp_rkap_key_set_from_auth(DHCPRKAPKey *key, const void *auth, size_t auth_len);

/* Verifies a received Reconfigure or DHCPFORCERENEW message. 'auth' must point to the body of the message's
 * Authentication option, within 'message'. On success the replay detection value is recorded. Returns
 * -ENOKEY if no key is set, -EBADMSG for malformed options, -EOPNOTSUPP for other authentication protocols,
 * -ESTALE if the replay detection value is not larger than the last one, and -EPERM if the digest does not
 * match. */
int dhcp_rkap_verify(DHCPRKAPKey *key, const void *message, size_t message_len, const void *auth, size_t auth_len);
