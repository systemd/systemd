# SPDX-License-Identifier: LGPL-2.1-or-later

load("@tine//distribution:defs.bzl", "distribution")

# Buck only allows `distribution.select()` in a BUCK file or in a function that a BUCK file calls. The
# lists in packages.bzl are therefore plain dicts, and packages() turns them into a select.
def packages(layer: dict[str, list[str]]):
    return layer.get("all", []) + distribution.select({"DEFAULT": []} | {name: names for name, names in layer.items() if name != "all"})
