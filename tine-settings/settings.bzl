# SPDX-License-Identifier: LGPL-2.1-or-later

load("@tine//distribution:defs.bzl", "distribution")

SETTINGS = struct(
    tools_box = struct(
        additional_repositories = distribution.select({
            "DEFAULT": [],
            "fedora": ["root//:systemd.repository"],
        }),
        packages = [
            "squashfs-tools",
            "tar",
        ],
    ),
)
