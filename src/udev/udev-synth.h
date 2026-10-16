/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "udev-forward.h"

int manager_synthesize_change(Manager *manager, sd_device *dev);
