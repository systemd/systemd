/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

/* Parsed value of the systemd.firstboot= kernel command line option, honoured by systemd-firstboot,
 * homectl's firstboot logic and systemd-cryptenroll. */
typedef enum FirstBootMode {
        FIRSTBOOT_OFF,          /* "no": don't prompt, don't auto-configure */
        FIRSTBOOT_INTERACTIVE,  /* "yes" or unset: prompt as needed */
        FIRSTBOOT_HEADLESS,     /* "headless": auto-configure, but never prompt */
        _FIRSTBOOT_MODE_MAX,
        _FIRSTBOOT_MODE_INVALID = -EINVAL,
} FirstBootMode;

DECLARE_STRING_TABLE_LOOKUP(firstboot_mode, FirstBootMode);

int firstboot_mode_from_cmdline(FirstBootMode *ret);
