/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/if_addr.h>

#if !HAVE_IFA_FLAGS /* 479840ffdbe4242e8a25349218c8e0859223aa35 (3.14) */
#define IFA_FLAGS 8
#endif

#ifndef IFA_F_MANAGETEMPADDR /* 53bd674915379d91e0e505332c89741b34eab05c (3.14) */
#define IFA_F_MANAGETEMPADDR 0x100
#endif

#ifndef IFA_F_NOPREFIXROUTE /* 761aac737eb11901c382a3f021dead59a26983fc (3.14) */
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#ifndef IFA_F_MCAUTOJOIN /* 93a714d6b53d87872e552dbb273544bdeaaf6e12 (4.1) */
#define IFA_F_MCAUTOJOIN 0x400
#endif
