/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bootspec.h"

int boot_config_load_and_select(BootConfig *config, const char *esp_path, dev_t esp_devid, const char *xbootldr_path, dev_t xbootldr_devid);
