/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_LINUX_CAN_VXCAN_H /* linux@a8f820a380a2a06fc4fe1a54159067958f800929 (4.12) */
#include <linux/can/vxcan.h>
#else
enum {
        VXCAN_INFO_UNSPEC,
        VXCAN_INFO_PEER,

        __VXCAN_INFO_MAX
#define VXCAN_INFO_MAX        (__VXCAN_INFO_MAX - 1)
};
#endif
