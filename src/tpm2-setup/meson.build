# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-tpm2-setup',
                'sources' : files('tpm2-setup.c'),
                'conditions' : [
                        'ENABLE_BOOTLOADER',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
                'dependencies' : [
                        libopenssl,
                ],
        },
        libexec_template + {
                'name' : 'systemd-tpm2-clear',
                'sources' : files('tpm2-clear.c'),
                'conditions' : [
                        'ENABLE_BOOTLOADER',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
        },
        generator_template + {
                'name' : 'systemd-tpm2-generator',
                'sources' : files('tpm2-generator.c'),
                'conditions' : [
                        'ENABLE_BOOTLOADER',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
        },
]

if conf.get('ENABLE_BOOTLOADER') == 1 and conf.get('HAVE_OPENSSL') == 1 and conf.get('HAVE_TPM2') == 1
        nvpcrs = [ 'cryptsetup',
                   'hardware',
                   'verity']
        foreach n : nvpcrs
                custom_target(
                        input : 'nvpcr/' + n + '.nvpcr.in',
                        output : n + '.nvpcr',
                        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                        install : true,
                        install_dir : prefixdir / 'lib/nvpcr')
        endforeach
endif
