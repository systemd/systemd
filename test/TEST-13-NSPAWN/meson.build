args = [
        '--kernel-command-line-extra=' + ' '.join([
                'apparmor=0',
                'selinux=0',
                'enforcing=0',
                'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-13.units:/usr/lib/systemd/tests/testdata/units:',
                'systemd.unit=testsuite.target',
                'systemd.wants=testsuite-13.service',
                'systemd.wants=end.service',
                'systemd.mount-extra=/usr/share/testsuite-13-container-template.raw:/run/extensions/testsuite-13-container-template.raw::bind',
                'systemd.wants=systemd-sysext.service',
        ])
]
test_params += {
        'mkosi_args': args,
}
