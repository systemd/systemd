# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMDS') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-imdsd',
                'public' : true,
                'sources' : files('imdsd.c'),
                'extract' : files('imds-util.c'),
        },
        libexec_template + {
                'name' : 'systemd-imds',
                'public' : true,
                'sources' : files('imds-tool.c'),
                'objects' : ['systemd-imdsd'],
        },
        generator_template + {
                'name' : 'systemd-imds-generator',
                'sources' : files('imds-generator.c'),
                'objects' : ['systemd-imdsd'],
        },
]

install_data(
        'io.systemd.imds.policy',
        install_dir : polkitpolicydir)
