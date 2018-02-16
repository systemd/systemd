# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Zbigniew Jędrzejewski-Szmek
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

systemd_importd_sources = files('''
        importd.c
'''.split())

systemd_pull_sources = files('''
        pull.c
        pull-raw.c
        pull-raw.h
        pull-tar.c
        pull-tar.h
        pull-job.c
        pull-job.h
        pull-common.c
        pull-common.h
        import-common.c
        import-common.h
        import-compress.c
        import-compress.h
        curl-util.c
        curl-util.h
        qcow2-util.c
        qcow2-util.h
'''.split())

systemd_import_sources = files('''
        import.c
        import-raw.c
        import-raw.h
        import-tar.c
        import-tar.h
        import-common.c
        import-common.h
        import-compress.c
        import-compress.h
        qcow2-util.c
        qcow2-util.h
'''.split())

systemd_export_sources = files('''
        export.c
        export-tar.c
        export-tar.h
        export-raw.c
        export-raw.h
        import-common.c
        import-common.h
        import-compress.c
        import-compress.h
'''.split())

if conf.get('ENABLE_IMPORTD') == 1
        install_data('org.freedesktop.import1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.import1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.import1.policy',
                     install_dir : polkitpolicydir)

        install_data('import-pubring.gpg',
                     install_dir : rootlibexecdir)
        # TODO: shouldn't this be in pkgdatadir?
endif

tests += [
        [['src/import/test-qcow2.c',
          'src/import/qcow2-util.c',
          'src/import/qcow2-util.h'],
         [libshared],
         [libz],
         'HAVE_ZLIB', 'manual'],
]
