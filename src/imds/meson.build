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
        libexec_template + {
                'name' : 'systemd-imds',
                'public' : true,
                'sources' : files('imds-tool.c', 'imds-util.c'),
        },
        generator_template + {
                'name' : 'systemd-imds-generator',
                'public' : true,
                'sources' : files('imds-generator.c'),
        },
]

install_data(
        '85-imds-early.network',
        install_dir : libexecdir / 'imds')
