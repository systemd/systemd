in_files = '''
        systemd.bg.catalog
        systemd.be.catalog
        systemd.be@latin.catalog
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
build_catalog_dir = meson.current_build_dir()

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
