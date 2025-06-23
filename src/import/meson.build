# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMPORTD') != 1
        subdir_done()
endif

systemd_importd_sources = files(
        'importd.c',
)
systemd_importd_extract_sources = files(
        'import-common.c',
        'import-compress.c',
        'qcow2-util.c',
)

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
        'import-fs.c',
)

systemd_export_sources = files(
        'export.c',
        'export-tar.c',
        'export-raw.c',
)

common_deps = [
        libbzip2,
        libcurl,
        libxz,
        libz,
        libzstd,
]

executables += [
        libexec_template + {
                'name' : 'systemd-importd',
                'dbus' : true,
                'sources' : systemd_importd_sources + systemd_importd_extract_sources,
                'extract' : systemd_importd_extract_sources,
                'dependencies' : [common_deps, threads],
        },
        libexec_template + {
                'name' : 'systemd-pull',
                'public' : true,
                'sources' : systemd_pull_sources,
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps + [
                        libopenssl,
                ],
        },
        libexec_template + {
                'name' : 'systemd-import',
                'public' : true,
                'sources' : systemd_import_sources,
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
        },
        libexec_template + {
                'name' : 'systemd-import-fs',
                'public' : true,
                'sources' : systemd_import_fs_sources,
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
        },
        libexec_template + {
                'name' : 'systemd-export',
                'public' : true,
                'sources' : systemd_export_sources,
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
        },
        executable_template + {
                'name' : 'importctl',
                'public' : true,
                'sources' : files('importctl.c'),
        },
        generator_template + {
                'name' : 'systemd-import-generator',
                'sources' : files('import-generator.c'),
        },
        test_template + {
                'sources' : files('test-qcow2.c'),
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
                'conditions' : ['HAVE_ZLIB'],
                'type' : 'manual',
        },
]

install_data('org.freedesktop.import1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.import1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.import1.policy',
             install_dir : polkitpolicydir)

install_data('import-pubring.pgp',
             install_dir : libexecdir)
# TODO: shouldn't this be in pkgdatadir?
