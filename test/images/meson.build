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

images += [
        image_template + {
                'name' : 'minimal-base',
                'directory' : meson.current_source_dir() / 'minimal-base',
                'output' : ['minimal-base'],
                'install' : false,
                'depend_files' : files(
                        'minimal-base/mkosi.conf',
                        'minimal-base/mkosi.conf.d/10-arch.conf',
                        'minimal-base/mkosi.conf.d/10-centos-fedora.conf',
                        'minimal-base/mkosi.conf.d/10-debian-ubuntu.conf',
                        'minimal-base/mkosi.extra/etc/resolv.conf',
                ),
        }
]

foreach name : ['minimal_0', 'minimal_1']
        images += [
                image_template + {
                        'name' : name,
                        'directory' : meson.current_source_dir() / name,
                        'base_trees' : ['minimal-base'],
                        'output' : [
                                '@0@.raw'.format(name),
                                '@0@.root-@1@.raw'.format(name, dps_arch),
                                '@0@.root-@1@-verity.raw'.format(name, dps_arch),
                                '@0@.root-@1@-verity-sig.raw'.format(name, dps_arch),
                        ],
                        'install' : install_tests,
                        'install_dir' : testdata_dir,
                        'depends' : ['minimal-base'],
                        'depend_files' : files(
                                '@0@/mkosi.conf'.format(name),
                                '@0@/mkosi.extra/opt/some_file'.format(name),
                                '@0@/mkosi.extra/usr/lib/systemd/system/minimal-app0.service'.format(name),
                                '@0@/mkosi.extra/var/lib/app1/foo'.format(name),
                                '@0@/mkosi.postinst'.format(name),
                        ),
                }
        ]
endforeach
