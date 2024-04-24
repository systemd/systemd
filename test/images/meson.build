# SPDX-License-Identifier: LGPL-2.1-or-later

dps_arch = {
        'aarch64'     : 'arm64',
        'arm'         : 'arm',
        'loongarch32' : 'loongarch32',
        'loongarch64' : 'loongarch64',
        'riscv32'     : 'riscv32',
        'riscv64'     : 'riscv64',
        'x86_64'      : 'x86-64',
        'x86'         : 'x86',
}.get(host_machine.cpu_family(), '')

minimal_base = custom_target('minimal-base',
        output : ['minimal-base'],
        console : true,
        install : want_tests != 'false',
        install_dir : testdata_dir,
        command : [
                'mkosi',
                '--directory', meson.current_source_dir() / 'minimal-base',
                '--output-dir', meson.current_build_dir(),
                '--extra-search-path', project_build_root,
                '--force',
                'build',
        ],
        depend_files : files(
                'minimal-base/mkosi.conf',
                'minimal-base/mkosi.conf.d/10-arch.conf',
                'minimal-base/mkosi.conf.d/10-centos-fedora.conf',
                'minimal-base/mkosi.conf.d/10-debian-ubuntu.conf',
                'minimal-base/mkosi.extra/etc/resolv.conf',
        )
)

minimal_0 = custom_target('minimal_0',
        output : [
                'minimal_0.raw',
                'minimal_0.root-@0@.raw'.format(dps_arch),
                'minimal_0.root-@0@-verity.raw'.format(dps_arch),
                'minimal_0.root-@0@-verity-sig.raw'.format(dps_arch),
        ],
        console : true,
        install : want_tests != 'false',
        install_dir : testdata_dir,
        command : [
                'mkosi',
                '--directory', meson.current_source_dir() / 'minimal_0',
                '--base-tree', meson.current_build_dir() / 'minimal-base',
                '--output-dir', meson.current_build_dir(),
                '--extra-search-path', project_build_root,
                '--verity-key', project_source_root / 'mkosi.key',
                '--verity-certificate', project_source_root / 'mkosi.crt',
                '--force',
                'build',
        ],
        depend_files : files(
                'minimal_0/mkosi.conf',
                'minimal_0/mkosi.extra/opt/some_file',
                'minimal_0/mkosi.extra/usr/lib/systemd/system/minimal-app0.service',
                'minimal_0/mkosi.extra/var/lib/app1/foo',
                'minimal_0/mkosi.postinst',
        )
)

minimal_1 = custom_target('minimal_1',
        output : [
                'minimal_1.raw',
                'minimal_1.root-@0@.raw'.format(dps_arch),
                'minimal_1.root-@0@-verity.raw'.format(dps_arch),
                'minimal_1.root-@0@-verity-sig.raw'.format(dps_arch),
        ],
        console : true,
        install : want_tests != 'false',
        install_dir : testdata_dir,
        command : [
                'mkosi',
                '--directory', meson.current_source_dir() / 'minimal_1',
                '--base-tree', meson.current_build_dir() / 'minimal-base',
                '--output-dir', meson.current_build_dir(),
                '--extra-search-path', project_build_root,
                '--verity-key', project_source_root / 'mkosi.key',
                '--verity-certificate', project_source_root / 'mkosi.crt',
                '--force',
                'build',
        ],
        depend_files : files(
                'minimal_1/mkosi.conf',
                'minimal_1/mkosi.extra/opt/some_file',
                'minimal_1/mkosi.extra/usr/lib/systemd/system/minimal-app0.service',
                'minimal_1/mkosi.extra/var/lib/app1/foo',
                'minimal_1/mkosi.postinst',
        )
)

images += [
        minimal_0,
        minimal_1,
]
