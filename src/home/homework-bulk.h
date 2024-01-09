/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright © 2024 GNOME Foundation Inc.
 *      Original Author: Adrian Vovk
*/

#pragma once

#include "user-record.h"

int home_reconcile_bulk_dirs(UserRecord *h, int root_fd, int reconciled);
