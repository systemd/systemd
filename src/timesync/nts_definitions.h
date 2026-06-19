/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#define NTS_MAX_PACKET_SIZE 1280u

/* numeric id's for the NTS record type */

#define NTS_REC_EndOfMessage 0u  /* critical */
#define NTS_REC_NextProto 1u     /* critical */
#define NTS_REC_Error 2u         /* critical */
#define NTS_REC_Warning 3u       /* critical */
#define NTS_REC_AEADAlgorithm 4u /* may be critical */
#define NTS_REC_NTPv4Cookie 5u   /* never critical */
#define NTS_REC_NTPv4Server 6u   /* never critical by clients, may be critical by servers */
#define NTS_REC_NTPv4Port 7u     /* never critical by clients, may be critical by servers */
#define NTS_REC_Chrony_BugWorkaround 1024u /* see: https://chrony-project.org/doc/spec/nts-compliant-128gcm.html */

/* numeric id's for the various AEAD schemes */

#define NTS_AEAD_AES_SIV_CMAC_256 15u
#define NTS_AEAD_AES_SIV_CMAC_384 16u
#define NTS_AEAD_AES_SIV_CMAC_512 17u
#define NTS_AEAD_AES_128_GCM_SIV  30u
#define NTS_AEAD_AES_256_GCM_SIV  31u

/* numeric id's for the protocol type */

#define NTS_PROTO_NTPv4 0u

/* numeric id's for the internals of NTS extension fields */

#define NTS_EF_UniqueIdentifier  0x0104u
#define NTS_EF_Cookie            0x0204u
#define NTS_EF_CookiePlaceholder 0x0304u
#define NTS_EF_AuthEncExtFields  0x0404u
#define NTS_EF_NoOpField         0x0200u
