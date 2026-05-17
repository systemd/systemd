#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Generate sample input for fuzz-bootspec"""

import json
import sys
from pathlib import Path

config = Path(sys.argv[1]).read_text()
loader = [entry for entry in Path(sys.argv[2]).read_text(encoding='utf-16-le').split('\0') if len(entry) > 2]
entries = [(Path(name).name, Path(name).read_text()) for name in sys.argv[3:]]

data = {
    'config': config,
    'entries': entries,
    'loader': loader,
}

print(json.dumps(data, indent=4))
