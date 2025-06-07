# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'configuration' : integration_test_template['configuration'] + {
                        'service' : integration_test_template['configuration']['service'] + {
                                'NotifyAccess' : 'all',
                                # Issue: https://github.com/systemd/systemd/issues/2691
                                'ExecStop' : 'sh -c \'kill -SEGV $$$$\'',
                                'RemainAfterExit' : 'yes',
                                'TimeoutStopSec' : '270s',
                        },
                },
        },
]
