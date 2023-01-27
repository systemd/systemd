# SPDX-License-Identifier: LGPL-2.1-or-later

in_files = [
        'systemd.be.catalog',
        'systemd.be@latin.catalog',
        'systemd.bg.catalog',
        'systemd.catalog',
        'systemd.da.catalog',
        'systemd.de.catalog',
        'systemd.fr.catalog',
        'systemd.hr.catalog',
        'systemd.hu.catalog',
        'systemd.it.catalog',
        'systemd.ko.catalog',
        'systemd.pl.catalog',
        'systemd.pt_BR.catalog',
        'systemd.ru.catalog',
        'systemd.sr.catalog',
        'systemd.zh_CN.catalog',
        'systemd.zh_TW.catalog',
]

support_url = get_option('support-url')
support_sed = 's~%SUPPORT_URL%~@0@~'.format(support_url)

foreach file : in_files
        catalogs += custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [sed, support_sed, '@INPUT@'],
                capture : true,
                install : true,
                install_dir : catalogdir)
endforeach

meson.add_install_script('sh', '-c',
                         'test -n "$DESTDIR" || @0@/journalctl --update-catalog'.format(rootbindir))
