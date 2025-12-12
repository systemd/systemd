#!/usr/bin/python
# SPDX-License-Identifier: MIT-0

import platform
os_release = platform.freedesktop_os_release()

pretty_name = os_release.get('PRETTY_NAME', 'Linux')
print(f'Running on {pretty_name!r}')

if 'fedora' in [os_release.get('ID', 'linux'),
                *os_release.get('ID_LIKE', '').split()]:
    print('Looks like Fedora!')
