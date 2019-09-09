#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

# Generate autosuspend rules for devices that have been whitelisted (IE tested)
# by the ChromeOS team. Please keep this script in sync with:
# https://chromium.googlesource.com/chromiumos/platform2/+/master/power_manager/udev/gen_autosuspend_rules.py

import sys
import chromeos.gen_autosuspend_rules

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.stdout = open(sys.argv[1], 'w')
    chromeos.gen_autosuspend_rules.main()
