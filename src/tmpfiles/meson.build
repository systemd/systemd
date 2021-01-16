# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_tmpfiles_sources = files(
        'tmpfiles.c',
        'offline-passwd.c',
        'offline-passwd.h')

tests += [
        [['src/tmpfiles/test-offline-passwd.c',
          'src/tmpfiles/offline-passwd.c',
          'src/tmpfiles/offline-passwd.h']],
]
