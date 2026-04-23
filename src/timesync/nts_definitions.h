/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#pragma once

/* numeric id's for the NTS record type */

#define NTS_REC_EndOfMessage 0  /* critical */
#define NTS_REC_NextProto 1     /* critical */
#define NTS_REC_Error 2         /* critical */
#define NTS_REC_Warning 3       /* critical */
#define NTS_REC_AEADAlgorithm 4 /* may be critical */
#define NTS_REC_NTPv4Cookie 5   /* never critical */
#define NTS_REC_NTPv4Server 6   /* never critical by clients, may be critical by servers */
#define NTS_REC_NTPv4Port 7     /* never critical by clients, may be critical by servers */
#define NTS_REC_Chrony_BugWorkaround 1024 /* see: https://chrony-project.org/doc/spec/nts-compliant-128gcm.html */

/* numeric id's for the various AEAD schemes */

#define NTS_AEAD_AES_SIV_CMAC_256 15
#define NTS_AEAD_AES_SIV_CMAC_384 16
#define NTS_AEAD_AES_SIV_CMAC_512 17
#define NTS_AEAD_AES_128_GCM_SIV  30
#define NTS_AEAD_AES_256_GCM_SIV  31

/* numeric id's for the protocol type */

#define NTS_PROTO_NTPv4 0

/* numeric id's for the internals of NTS extension fields */

#define NTS_EF_UniqueIdentifier  0x0104
#define NTS_EF_Cookie            0x0204
#define NTS_EF_CookiePlaceholder 0x0304
#define NTS_EF_AuthEncExtFields  0x0404
#define NTS_EF_NoOpField         0x0200
