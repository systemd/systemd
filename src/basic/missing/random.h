/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if USE_SYS_RANDOM_H
#include <sys/random.h>
#else
#include <linux/random.h>
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
