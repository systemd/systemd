#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import re
import subprocess
import sys

def main():
    build_dir = sys.argv[1]

    out = subprocess.run(["meson", "introspect", "--installed", build_dir],
                         stdout=subprocess.PIPE, check=True)
    files = json.loads(out.stdout)
    for file in sorted(files.values()):
        if re.search("^/usr/lib/systemd/(system|user)/", file) and not file.endswith(".conf"):
            print(file)

if __name__ == "__main__":
    main()
