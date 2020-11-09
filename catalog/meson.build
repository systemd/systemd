# SPDX-License-Identifier: LGPL-2.1-or-later

in_files = '''
        systemd.bg.catalog
        systemd.be.catalog
        systemd.be@latin.catalog
        systemd.de.catalog
        systemd.fr.catalog
        systemd.it.catalog
        systemd.pl.catalog
        systemd.pt_BR.catalog
        systemd.ru.catalog
        systemd.zh_CN.catalog
        systemd.zh_TW.catalog
        systemd.catalog
'''.split()

support_url = get_option('support-url')
support_sed = 's~%SUPPORT_URL%~@0@~'.format(support_url)

foreach file : in_files
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [sed, support_sed, '@INPUT@'],
                capture : true,
                install : true,
                install_dir : catalogdir)
endforeach

meson.add_install_script('sh', '-c',
                         'test -n "$DESTDIR" || @0@/journalctl --update-catalog'
                         .format(rootbindir))
