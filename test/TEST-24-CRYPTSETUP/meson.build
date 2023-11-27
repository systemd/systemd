test_params += {
        'mkosi_image_name': 'testsuite-24-cryptsetup',
        'hook_module': meson.current_source_dir() / 'hook.py',
}
testsuite_24_keydev_root = custom_target('testsuite_24_keyfile',
        output : 'testsuite-24-cryptsetup-keydev',
        input : meson.current_source_dir() / 'keyfile',
        command : ['install', '--mode=0600', '-D', '@INPUT@', '@OUTPUT@' / 'keyfile'],
)
systemd_repart_wrapper = find_program('systemd-repart-wrapper.sh')
testsuite_24_keyfile = testsuite_24_keydev_root.full_path() / 'keyfile'
# TODO: It is possible for the output file to need to be regenerated
# because a dependency changed, but `--empty=create` requires the file to not exist
# Identify the right options to force recreate the file.
testsuite_24_keydev = custom_target('testsuite_24_keydev',
        output : 'testsuite-24-cryptsetup-keydev.raw',
        command : [
                systemd_repart_wrapper,
                '--systemd-repart', executables_by_name['systemd-repart'],
                '@OUTPUT@',
                '--',
                '--dry-run=no',
                '--size=auto',
                '--offline=true',
                '--root', testsuite_24_keydev_root,
                '--definitions', meson.current_source_dir() / 'keydev.repart',
        ],
        depends : [testsuite_24_keydev_root],
)
testsuite_24_mkosi = custom_target('testsuite_24_mkosi',
        build_always_stale : true,
        output : 'testsuite_24',
        console : true,
        command: [build_system_mkosi_wrapper, test_params['mkosi_image_name'], '@OUTPUT@', '--passphrase', testsuite_24_keyfile]
)

test_params += {
        'mkosi_output_path': testsuite_24_mkosi,
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'rd.luks=1',
                        'luks.name=0d318174-56b0-4d6e-a324-ac1e7e7d235d=test24_varcrypt',
                        'luks.key=0d318174-56b0-4d6e-a324-ac1e7e7d235d=/keyfile:LABEL=varcrypt_keydev',
                        'luks.options=0d318174-56b0-4d6e-a324-ac1e7e7d235d=x-initrd.attach',
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-24.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-24.service',
                        'systemd.wants=end.service',
                ]),
                '--credential=fstab.extra="/dev/mapper/test24_varcrypt    /var    ext4    defaults 0 1"',
                '--qemu-args=-drive format=raw,cache=unsafe,file=' + testsuite_24_keydev.full_path().replace(',', ',,'),
        ],
        'depends': [testsuite_24_mkosi, executables_by_name['systemd-dissect'], testsuite_24_keydev],
}
