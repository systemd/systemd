/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation
  Authors:
        Nathaniel Chen <nathaniel.chen@intel.com>
***/

#include <stdbool.h>

int mac_smack_setup(bool *loaded_policy);
