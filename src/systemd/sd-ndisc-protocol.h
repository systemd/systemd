/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdndiscprotocolfoo
#define foosdndiscprotocolfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* Neighbor Discovery Options, RFC 4861, Section 4.6 and
 * https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-5 */
enum {
        SD_NDISC_OPTION_SOURCE_LL_ADDRESS       = 1,   /* RFC4861 */
        SD_NDISC_OPTION_TARGET_LL_ADDRESS       = 2,   /* RFC4861 */
        SD_NDISC_OPTION_PREFIX_INFORMATION      = 3,   /* RFC4861 */
        SD_NDISC_OPTION_REDIRECTED_HEADER       = 4,   /* RFC4861 */
        SD_NDISC_OPTION_MTU                     = 5,   /* RFC4861 */
        SD_NDISC_OPTION_NBMA_SHORTCUT_LIMIT     = 6,   /* RFC2491 */
        SD_NDISC_OPTION_ADVERTISEMENT_INTERVAL  = 7,   /* RFC6275 */
        SD_NDISC_OPTION_HOME_AGENT              = 8,   /* RFC6275 */
        SD_NDISC_OPTION_SOURCE_ADDRESS_LIST     = 9,   /* RFC3122 */
        SD_NDISC_OPTION_TARGET_ADDRESS_LIST     = 10,  /* RFC3122 */
        SD_NDISC_OPTION_CGA                     = 11,  /* RFC3971 */
        SD_NDISC_OPTION_RSA_SIGNATURE           = 12,  /* RFC3971 */
        SD_NDISC_OPTION_TIMESTAMP               = 13,  /* RFC3971 */
        SD_NDISC_OPTION_NONCE                   = 14,  /* RFC3971 */
        SD_NDISC_OPTION_TRUST_ANCHOR            = 15,  /* RFC3971 */
        SD_NDISC_OPTION_CERTIFICATE             = 16,  /* RFC3971 */
        SD_NDISC_OPTION_IP_ADDRESS_PREFIX       = 17,  /* RFC5568 */
        SD_NDISC_OPTION_NEW_ROUTER_PREFIX       = 18,  /* RFC4068 */
        SD_NDISC_OPTION_LL_ADDRESS              = 19,  /* RFC5568 */
        SD_NDISC_OPTION_NEIGHBOR_ACKNOWLEDGMENT = 20,  /* RFC5568 */
        SD_NDISC_OPTION_PVD_ID_ROUTER           = 21,  /* RFC8801 */
        /* 22 is unassigned yet */
        SD_NDISC_OPTION_MAP                     = 23,  /* RFC4140 */
        SD_NDISC_OPTION_ROUTE_INFORMATION       = 24,  /* RFC4191 */
        SD_NDISC_OPTION_RDNSS                   = 25,  /* RFC5006, RFC8106 */
        SD_NDISC_OPTION_FLAGS_EXTENSION         = 26,  /* RFC5175 */
        SD_NDISC_OPTION_HANDOVER_KEY_REQUEST    = 27,  /* RFC5269 */
        SD_NDISC_OPTION_HANDOVER_KEY_REPLY      = 28,  /* RFC5269 */
        SD_NDISC_OPTION_HANDOVER_ASSIST         = 29,  /* RFC5271 */
        SD_NDISC_OPTION_MOBILE_NODE_ID          = 30,  /* RFC5271 */
        SD_NDISC_OPTION_DNSSL                   = 31,  /* RFC8106 */
        SD_NDISC_OPTION_PROXY_SIGNATURE         = 32,  /* RFC6496 */
        SD_NDISC_OPTION_REGISTRATION            = 33,  /* RFC6775 */
        SD_NDISC_OPTION_6LOWPAN                 = 34,  /* RFC6775 */
        SD_NDISC_OPTION_AUTHORITATIVE_BORDER    = 35,  /* RFC6775 */
        SD_NDISC_OPTION_6LOWPAN_CAPABILITY      = 36,  /* RFC7400 */
        SD_NDISC_OPTION_CAPTIVE_PORTAL          = 37,  /* RFC8910 */
        SD_NDISC_OPTION_PREF64                  = 38,  /* RFC8781 */
        SD_NDISC_OPTION_CRYPTO_ID               = 39,  /* RFC8928 */
        SD_NDISC_OPTION_NDP_SIGNATURE           = 40,  /* RFC8928 */
        SD_NDISC_OPTION_RESOURCE_DIRECTORY      = 41,  /* RFC9176 */
        /* 42-137 are unassigned yet */
        SD_NDISC_OPTION_CARD_REQUEST            = 138, /* RFC4065 */
        SD_NDISC_OPTION_CARD_REPLY              = 139, /* RFC4065 */
        /* 140-143 are unassigned yet */
        SD_NDISC_OPTION_ENCRYPTED_DNS           = 144  /* RFC9463 */
        /* 145-252 are unassigned yet */
        /* 253-254 are for experiment, see RFC4727 */
};

/* Route preference, RFC 4191, Section 2.1 */
enum {
        SD_NDISC_PREFERENCE_MEDIUM   = 0U,
        SD_NDISC_PREFERENCE_HIGH     = 1U,
        SD_NDISC_PREFERENCE_RESERVED = 2U,
        SD_NDISC_PREFERENCE_LOW      = 3U
};

_SD_END_DECLARATIONS;

#endif
