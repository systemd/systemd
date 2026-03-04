# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMDS') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-imdsd',
                'public' : true,
                'sources' : files('imdsd.c', '../import/curl-util.c', 'imds-util.c'),
                'dependencies' : [ libcurl ],
        },
]

install_data(
        'io.systemd.imds.policy',
        install_dir : polkitpolicydir)
