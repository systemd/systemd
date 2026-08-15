# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                # knot uses lmdb which uses O_SYNC which will fail with EINVAL
                # when running under --suppress-sync.
                'suppress-sync' : false,
        },
]
