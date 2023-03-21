# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_importd_sources = files(
        'importd.c')

systemd_pull_sources = files(
        'pull.c',
        'pull-raw.c',
        'pull-tar.c',
        'pull-job.c',
        'pull-common.c',
        'curl-util.c',
)

systemd_import_sources = files(
        'import.c',
        'import-raw.c',
        'import-tar.c',
)

systemd_import_fs_sources = files(
        'import-fs.c')

systemd_export_sources = files(
        'export.c',
        'export-tar.c',
        'export-raw.c',
)

if conf.get('ENABLE_IMPORTD') == 1
        lib_import_common = static_library(
                'import-common',
                'import-common.c',
                'import-compress.c',
                'qcow2-util.c',
                include_directories : includes,
                dependencies : [libbzip2,
                                libxz,
                                libz,
                                userspace],
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
        {
                'sources' : files(
                        'test-qcow2.c',
                        'qcow2-util.c',
                ),
                'dependencies' : libz,
                'condition' : 'HAVE_ZLIB',
                'type' : 'manual',
        },
]
