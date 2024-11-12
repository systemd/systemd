# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

subdir('cryptsetup-tokens')

systemd_cryptsetup_sources = files(
        'cryptsetup-keyfile.c',
        'cryptsetup.c',
)

if conf.get('HAVE_P11KIT') == 1
        systemd_cryptsetup_sources += files('cryptsetup-pkcs11.c')
endif

executables += [
        executable_template + {
                'name' : 'systemd-cryptsetup',
                'public' : true,
                'sources' : systemd_cryptsetup_sources,
                'dependencies' : [
                        libcryptsetup,
                        libopenssl,
                        libp11kit_cflags,
                ],
        },
        generator_template + {
                'name' : 'systemd-cryptsetup-generator',
                'sources' : files('cryptsetup-generator.c'),
        },
]

# symlink for backwards compatibility after rename
meson.add_install_script(sh, '-c',
                         ln_s.format(bindir / 'systemd-cryptsetup',
                                     libexecdir / 'systemd-cryptsetup'))
