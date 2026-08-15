#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Fuzzy translations are always bogus, but the meson integration doesn't allow overriding. With this wrapper
we can skip them.
"""

import os
import shutil
import sys

msgmerge = shutil.which('msgmerge')
if msgmerge is None:
    sys.exit('msgmerge-no-fuzzy: msgmerge not found in PATH')

os.execv(msgmerge, [msgmerge, '--no-fuzzy-matching', *sys.argv[1:]])
