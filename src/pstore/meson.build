# SPDX-License-Identifier: LGPL-2.1+

systemd_pstore_sources = files('''
        pstore.c
'''.split())

#pstorectl_sources = files('pstorectl.c')

if conf.get('ENABLE_PSTORE') == 1
        install_data('pstore.conf',
                     install_dir : pkgsysconfdir)
endif

#tests += [
#        [['src/pstore/test-pstore.c',
#          'src/pstore/pstore.c',
#          'src/pstore/pstore.h'],
#         [],
#         [],
#         'ENABLE_PSTORE', 'manual'],
#]
