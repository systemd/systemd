test_params += {
        'mkosi_args' : [
                '--kernel-command-line-extra',
                ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        f'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-@test_number@.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        f'systemd.wants=@test_unit_name@',
                        'systemd.mount-extra=/usr/share/testsuite-69-shutdown.raw:/run/extensions/testsuite-69-shutdown.raw::bind',
                ]),
        ],
        'hook_module' : meson.current_source_dir() / 'hook.py',
}
