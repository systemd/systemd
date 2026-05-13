# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                # Newer tar started using openat2() (without openat() fallback) which
                # we currently filter out completely in nspawn with --suppress-sync
                'suppress-sync' : false,
        },
]
