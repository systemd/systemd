/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "varlink.h"

int vl_method_register(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata);
