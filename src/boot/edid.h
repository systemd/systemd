/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "edid-fundamental.h" /* IWYU pragma: export */
#include "efi.h"

EFI_STATUS edid_get_discovered_panel_id(char16_t **ret_panel);
