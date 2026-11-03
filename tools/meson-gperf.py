#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Run gperf and fail if it writes anything to stderr.

With --duplicates, gperf accepts a keyword that appears twice: it only warns about it on stderr and keeps
the first entry, silently dropping the second one. Our keyword tables have no hash collisions, so gperf is
otherwise silent, and any output on stderr indicates a duplicate keyword.
"""

import subprocess
import sys

result = subprocess.run(sys.argv[1:], stderr=subprocess.PIPE, text=True, errors='replace')
sys.stderr.write(result.stderr)
if result.returncode == 0 and result.stderr:
    sys.exit(f'{sys.argv[1]} wrote to stderr, see above. Does a keyword appear twice?')
sys.exit(result.returncode)
