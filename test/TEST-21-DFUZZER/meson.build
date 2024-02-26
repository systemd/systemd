args = [
        '--kernel-command-line-extra=' + ' '.join([
                'apparmor=0',
                'selinux=0',
                'enforcing=0',
                'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-21.units:/usr/lib/systemd/tests/testdata/units:',
                'systemd.unit=testsuite.target',
                'systemd.wants=testsuite-21.service',
                'systemd.wants=end.service',
                'systemd.mount-extra=/usr/share/testsuite-21-dfuzzer.raw:/run/extensions/testsuite-21-dfuzzer.raw::bind',
        ])
]
test_params += {
        'mkosi_args' : args,
        'timeout' : 1800,
}
