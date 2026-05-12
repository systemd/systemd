# SPDX-License-Identifier: LGPL-2.1-or-later

name = fs.name(meson.current_source_dir())

integration_tests += [
        integration_test_template + {
                'name' : name,
                'cmdline' : integration_test_template['cmdline'] + [
                        'rd.systemd.wants=initrd-run-mount.service',
                ],
                'exit-code' : 124,
                'vm' : true,
                'firmware' : 'linux',
        },
        # --no-state drops all initrd state including credentials. The test wrapper
        # normally injects SuccessAction=, FailureAction=, and StandardOutput= via
        # credential-based drop-ins, but those are lost after a stateless switch-root.
        # However, the new PID 1 re-imports credentials from SMBIOS since it starts
        # fresh (skip_setup=false), so vmm.notify_socket is restored and exit codes
        # work. Bake the remaining settings into the service file. Drop
        # user@4711.service dependency since its credentials are also lost.
        integration_test_template + {
                'name' : '@0@-no-state'.format(name),
                'configuration' : integration_test_template['configuration'] + {
                        'wants' : 'multi-user.target',
                        'after' : '',  # Drop user@4711.service ordering — its credentials are lost

                        'unit' : integration_test_template['configuration']['unit'] + {
                                'SuccessAction' : 'exit',
                                'SuccessActionExitStatus' : '123',
                                'FailureAction' : 'exit',
                                'FailureActionExitStatus' : '1',
                        },
                        'service' : integration_test_template['configuration']['service'] + {
                                'StandardOutput' : 'journal+console',
                        },
                },
                'cmdline' : integration_test_template['cmdline'] + [
                        'rd.systemd.wants=initrd-switch-root-no-state.service',
                ],
                'vm' : true,
                'firmware' : 'linux',
        },
]
