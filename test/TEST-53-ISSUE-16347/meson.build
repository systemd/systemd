p = run_command('date', '-u', '+%Y-%m-%dT%H:%M:%S', '-d', '+3 days', check: true)
rtc_base = p.stdout().strip()
test_params += {
        'mkosi_args': [
                '--kernel-command-line-extra=' + ' '.join([
                        'apparmor=0',
                        'selinux=0',
                        'enforcing=0',
                        'SYSTEMD_UNIT_PATH=/usr/lib/systemd/tests/testdata/testsuite-53.units:/usr/lib/systemd/tests/testdata/units:',
                        'systemd.unit=testsuite.target',
                        'systemd.wants=testsuite-53.service',
                        'systemd.wants=end.service',
                ]),
                f'--qemu-args=-rtc base=@rtc_base@',
        ],
}
