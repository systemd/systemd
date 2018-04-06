/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation
  Authors:
        Nathaniel Chen <nathaniel.chen@intel.com>
***/

int mac_smack_setup(bool *loaded_policy);
