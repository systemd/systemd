# SPDX-License-Identifier: LGPL-2.1-or-later

# This meson file can be used to run the integration tests without having to install any other dependencies
# as follows:
#
# mkosi genkey
# mkosi -f box -- meson setup testsuite test/integration-tests/standalone
# mkosi -f
# mkosi box -- meson test -C testsuite
#
project('systemd-testsuite',
        license : 'LGPLv2+',
        default_options: ['warning_level=2'],
        meson_version : '>= 0.62.0',
)

fs = import('fs')
mkosi = find_program('mkosi', required : true)

# meson refuses .. in subdir() so we use a symlink to trick it into accepting it anyway.
subdir('integration-tests')
