/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/rtnetlink.h>

#ifndef RTA_PREF /* c78ba6d64c78634a875d1e316676667cabfea256 (4.1) */
#define RTA_PREF 20
#endif

#ifndef RTA_EXPIRES /* 32bc201e1974976b7d3fea9a9b17bb7392ca6394 (4.5) */
#define RTA_EXPIRES 23
#endif

#ifndef RTAX_QUICKACK /* bcefe17cffd06efdda3e7ad679ea743236e6271a (3.11) */
#define RTAX_QUICKACK 15
#endif
