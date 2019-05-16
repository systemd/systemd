# SPDX-License-Identifier: LGPL-2.1+

systemd_pstore_sources = files('''
        pstore.c
'''.split())

if conf.get('ENABLE_PSTORE') == 1
        install_data('pstore.conf',
                     install_dir : pkgsysconfdir)
endif
