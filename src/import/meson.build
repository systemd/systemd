# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMPORTD') != 1
        subdir_done()
endif

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
                'sources' : files(
                        'importd.c',
                ),
                'extract' : files(
                        'oci-util.c',
                        'import-common.c',
                        'import-compress.c',
                        'qcow2-util.c',
                ),
                'dependencies' : [common_deps, threads],
        },
        libexec_template + {
                'name' : 'systemd-pull',
                'public' : true,
                'sources' : files(
                        'curl-util.c',
                        'pull.c',
                        'pull-common.c',
                        'pull-job.c',
                        'pull-oci.c',
                        'pull-raw.c',
                        'pull-tar.c',
                ),
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps + [
                        libopenssl,
                ],
        },
        libexec_template + {
                'name' : 'systemd-import',
                'public' : true,
                'sources' : files(
                        'import.c',
                        'import-raw.c',
                        'import-tar.c',
                ),
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
        },
        libexec_template + {
                'name' : 'systemd-import-fs',
                'public' : true,
                'sources' : files(
                        'import-fs.c',
                ),
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
        },
        libexec_template + {
                'name' : 'systemd-export',
                'public' : true,
                'sources' : files(
                        'export.c',
                        'export-tar.c',
                        'export-raw.c',
                ),
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
                'sources' : files('test-tar-extract.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-qcow2.c'),
                'objects' : ['systemd-importd'],
                'dependencies' : common_deps,
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-oci-util.c'),
                'objects': ['systemd-importd'],
                'dependencies' : common_deps,
        },
]

install_data('org.freedesktop.import1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.import1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.import1.service-for-session',
             install_dir : dbussessionservicedir,
             rename : 'org.freedesktop.import1.service')
install_data('org.freedesktop.import1.policy',
             install_dir : polkitpolicydir)

install_data('import-pubring.pgp',
             install_dir : libexecdir)
# TODO: shouldn't this be in pkgdatadir?

oci_registry_files = [
        'registry.docker.io.oci-registry',
        'registry.fedora.oci-registry',
]
oci_registry_symlinks = [
        [ 'default.oci-registry',              'registry.' + get_option('default-oci-registry')  + '.oci-registry' ],
        [ 'image.alpine.oci-registry',         'registry.docker.io.oci-registry'                                   ],
        [ 'image.archlinux.oci-registry',      'registry.docker.io.oci-registry'                                   ],
        [ 'image.debian.oci-registry',         'registry.docker.io.oci-registry'                                   ],
        [ 'image.fedora-minimal.oci-registry', 'registry.fedora.oci-registry'                                      ],
        [ 'image.fedora.oci-registry',         'registry.fedora.oci-registry'                                      ],
        [ 'image.ubuntu.oci-registry',         'registry.docker.io.oci-registry'                                   ],
]

foreach file : oci_registry_files
        install_data('oci-registry' / file,
                     install_dir : libexecdir / 'oci-registry')
endforeach

foreach tuple: oci_registry_symlinks
        install_symlink(tuple[0],
                        pointing_to : tuple[1],
                        install_dir : libexecdir / 'oci-registry')
endforeach
