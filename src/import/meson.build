# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_importd_sources = files(
        'importd.c')

systemd_pull_sources = files(
        'pull.c',
        'pull-raw.c',
        'pull-raw.h',
        'pull-tar.c',
        'pull-tar.h',
        'pull-job.c',
        'pull-job.h',
        'pull-common.c',
        'pull-common.h',
        'curl-util.c',
        'curl-util.h')

systemd_import_sources = files(
        'import.c',
        'import-raw.c',
        'import-raw.h',
        'import-tar.c',
        'import-tar.h')

systemd_import_fs_sources = files(
        'import-fs.c')

systemd_export_sources = files(
        'export.c',
        'export-tar.c',
        'export-tar.h',
        'export-raw.c',
        'export-raw.h')

if conf.get('ENABLE_IMPORTD') == 1
        lib_import_common = static_library(
                'import-common',
                'import-common.c',
                'import-common.h',
                'import-compress.c',
                'import-compress.h',
                'qcow2-util.c',
                'qcow2-util.h',
                include_directories : includes,
                dependencies : [libbzip2,
                                libxz,
                                libz],
                build_by_default : false)

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
        [files('test-qcow2.c',
               'qcow2-util.c',
               'qcow2-util.h'),
         [],
         [libz],
         [], 'HAVE_ZLIB', 'manual'],
]
