# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMPORTD') != 1
        subdir_done()
endif

systemd_importd_sources = files(
        'importd.c',
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

importd_common_sources = files(
        'import-common.c',
        'import-compress.c',
        'qcow2-util.c',
)

lib_import_common = static_library(
        'import-common',
        sources : importd_common_sources,
        include_directories : includes,
        dependencies : [
                libbzip2,
                libxz,
                libz,
                userspace,
        ],
        build_by_default : false)

common_libs = [
        lib_import_common,
        libshared,
]

common_deps = [
        libbzip2,
        libcurl,
        libxz,
        libz,
]

executables += [
        libexec_template + {
                'name' : 'systemd-importd',
                'dbus' : true,
                'conditions' : ['ENABLE_IMPORTD'],
                'sources' : systemd_importd_sources,
                'dependencies' : threads,
        },
        libexec_template + {
                'name' : 'systemd-pull',
                'public' : true,
                'conditions' : ['ENABLE_IMPORTD'],
                'sources' : systemd_pull_sources,
                'link_with' : common_libs,
                'dependencies' : common_deps + [
                        lib_openssl_or_gcrypt,
                ],
        },
        libexec_template + {
                'name' : 'systemd-import',
                'public' : true,
                'conditions' : ['ENABLE_IMPORTD'],
                'sources' : systemd_import_sources,
                'link_with' : common_libs,
                'dependencies' : common_deps,
        },
        libexec_template + {
                'name' : 'systemd-import-fs',
                'public' : true,
                'conditions' : ['ENABLE_IMPORTD'],
                'sources' : systemd_import_fs_sources,
                'link_with' : common_libs,
        },
        libexec_template + {
                'name' : 'systemd-export',
                'public' : true,
                'conditions' : ['ENABLE_IMPORTD'],
                'sources' : systemd_export_sources,
                'link_with' : common_libs,
                'dependencies' : common_deps,
        },
        executable_template + {
                'name' : 'importctl',
                'public' : true,
                'conditions' : ['ENABLE_IMPORTD'],
                'sources' : files('importctl.c'),
        },
        generator_template + {
                'name' : 'systemd-import-generator',
                'sources' : files('import-generator.c'),
                'conditions' : ['ENABLE_IMPORTD'],
        },
        test_template + {
                'sources' : files(
                        'test-qcow2.c',
                        'qcow2-util.c',
                ),
                'dependencies' : libz,
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

install_data('import-pubring.gpg',
             install_dir : libexecdir)
# TODO: shouldn't this be in pkgdatadir?
