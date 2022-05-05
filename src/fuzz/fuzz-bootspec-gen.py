# SPDX-License-Identifier: LGPL-2.1-or-later

"""Generate sample input for fuzz-bootspec"""

import json
import os
import sys

config = open(sys.argv[1]).read()
entries = [(os.path.basename(name), open(name).read())
           for name in sys.argv[2:]]

data = {
    'config': config,
    'entries': entries,
}

print(json.dumps(data, indent=4))
