# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_IMDS') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-imdsd',
                'public' : true,
                'sources' : files(
                        'imdsd.c',
                        'imds-util.c'
                ),
                'link_with' : [libcurlutil_static, libshared],
                'dependencies' : [libcurl],
        },
        libexec_template + {
                'name' : 'systemd-imds',
                'public' : true,
                'sources' : files(
                        'imds-tool.c',
                        'imds-util.c'
                ),
        },
        generator_template + {
                'name' : 'systemd-imds-generator',
                'sources' : files(
                        'imds-generator.c',
                        'imds-util.c'
                ),
        },
]

install_data(
        'io.systemd.imds.policy',
        install_dir : polkitpolicydir)
