# SPDX-License-Identifier: LGPL-2.1-or-later

# We'd give these more descriptive names but only alphanumeric characters are allowed.
add_test_setup('integration')
add_test_setup('shell', env : {'TEST_SHELL' : '1'})

integration_test_wrapper = find_program('integration-test-wrapper.py')
integration_tests = []
integration_test_template = {
        'mkosi-args' : [],
        'timeout' : 1800,
        'storage' : 'volatile',
        'priority' : 0,
        'firmware' : 'linux-noinitrd',
        'enabled' : true,
        'configuration' : {
                'memory-accounting' : 'no',
                'command' : '/usr/lib/systemd/tests/testdata/units/%N.sh',
                'wants' : 'multi-user.target user@4711.service',
                'after' : 'user@4711.service',
                'env' : {},
                'service' : {},
                'unit' : {},
        },
        'cmdline' : [],
        'credentials' : [],
        'qemu-args' : [],
        'exit-code' : 123,
        'vm' : false,
        'coredump-exclude-regex' : '',
        'sanitizer-exclude-regex' : '',
        'rtc' : false,
        'tpm' : false,
}

foreach dirname : [
        'TEST-17-UDEV',
]
        subdir(dirname)
endforeach

foreach integration_test : integration_tests
        integration_test_args = [
                '--meson-source-dir', meson.project_source_root(),
                '--meson-build-dir', meson.project_build_root(),
                '--name', integration_test['name'],
                '--storage', integration_test['storage'],
                '--firmware', integration_test['firmware'],
                '--exit-code', integration_test['exit-code'].to_string(),
                '--coredump-exclude-regex', integration_test['coredump-exclude-regex'],
                '--sanitizer-exclude-regex', integration_test['sanitizer-exclude-regex'],
                '--unit', '@0@.service'.format(integration_test['name'])
        ]

        if integration_test['vm']
                integration_test_args += ['--vm']
        endif

        if integration_test['rtc']
                integration_test_args += ['--rtc']
        endif

        if integration_test['tpm']
                integration_test_args += ['--tpm']
        endif

        if not integration_test['enabled']
                integration_test_args += ['--skip']
        endif

        if mkosi.found()
                integration_test_args += ['--mkosi', mkosi.full_path()]
        endif

        integration_test_args += ['--']

        if integration_test['cmdline'].length() > 0
                integration_test_args += [
                        '--kernel-command-line-extra=@0@'.format(' '.join(integration_test['cmdline']))
                ]
        endif

        foreach credential : integration_test['credentials']
                integration_test_args += ['--credential', credential]
        endforeach

        if integration_test['qemu-args'].length() > 0
                integration_test_args += ['--qemu-args=@0@'.format(' '.join(integration_test['qemu-args']))]
        endif

        integration_test_args += integration_test['mkosi-args']

        # We don't explicitly depend on the "mkosi" target because that means the image is rebuilt on every
        # "ninja -C build". Instead, the mkosi target has to be rebuilt manually before running the
        # integration tests with mkosi.
        test(
                integration_test['name'],
                integration_test_wrapper,
                args : integration_test_args,
                timeout : integration_test['timeout'],
                priority : integration_test['priority'],
                suite : 'integration-tests',
        )
endforeach
