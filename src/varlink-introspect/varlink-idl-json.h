/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"
#include "sd-varlink-idl.h"

/* Renders a compiled Varlink IDL interface definition as a structured JSON variant, for
 * machine consumption by the documentation pipeline (and other tooling). The output is
 * deterministic: symbol and field order follow declaration order, flags are emitted in a
 * fixed order, and no formatting depends on the environment. */

int varlink_idl_json_interface(const sd_varlink_interface *interface, sd_json_variant **ret);
