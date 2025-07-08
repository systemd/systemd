# SPDX-License-Identifier: LGPL-2.1-or-later

# This is lame, I know, but meson has no other include mechanism
subdir('rules')

want_man = get_option('man')
want_html = get_option('html')
xsltproc = find_program('xsltproc',
                        required : want_man.enabled() or want_html.enabled())
want_man = want_man.allowed() and xsltproc.found()
want_html = want_html.allowed() and xsltproc.found()

xsltproc_flags = [
        '--nonet',
        '--xinclude',
        '--maxdepth', '9000',
        '--stringparam', 'man.output.quietly', '1',
        '--stringparam', 'funcsynopsis.style', 'ansi',
        '--stringparam', 'man.authors.section.enabled', '0',
        '--stringparam', 'man.copyright.section.enabled', '0',
        '--stringparam', 'systemd.version', '@0@'.format(meson.project_version()),
        '--path',
        '@0@:@1@:@2@:@3@'.format(meson.current_build_dir(),
                             meson.current_source_dir(),
                             libshared_build_dir,
                             libcore_build_dir)]

custom_man_xsl = files('custom-man.xsl')
custom_html_xsl = files('custom-html.xsl')
xslt_cmd = [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags

custom_entities_ent = custom_target(
        input : 'custom-entities.ent.in',
        output : 'custom-entities.ent',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'])

man_page_depends += custom_entities_ent

man_pages = []
html_pages = []
source_xml_files = []
dbus_docs = []
foreach tuple : manpages
        stem = tuple[0]
        section = tuple[1]
        aliases = tuple[2]
        condition = tuple[3]

        xml = stem + '.xml'
        html = stem + '.html'
        man = stem + '.' + section

        manaliases = []
        htmlaliases = []
        foreach alias : aliases
                manaliases += alias + '.' + section
                htmlaliases += alias + '.html'
        endforeach

        mandirn = get_option('mandir') / ('man' + section)

        have = true
        foreach word : condition.split()
                if conf.get(word) != 1
                        have = false
                        break
                endif
        endforeach

        if have
                file = files(tuple[0] + '.xml')
                source_xml_files += file
                if tuple[0].startswith('org.freedesktop.')
                        dbus_docs += file
                endif

                if xsltproc.found()
                        p1 = custom_target(
                                input : xml,
                                output : [man] + manaliases,
                                command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
                                depends : man_page_depends,
                                install : want_man,
                                install_dir : mandirn)
                        man_pages += p1

                        p2 = []
                        foreach htmlalias : htmlaliases
                                link = custom_target(
                                        output : htmlalias,
                                        command : [ln, '-fs', html, '@OUTPUT@'])
                                if want_html
                                        install_symlink(htmlalias,
                                                        pointing_to : html,
                                                        install_dir : docdir / 'html')
                                        p2 += link
                                endif
                                html_pages += link
                        endforeach

                        p3 = custom_target(
                                input : xml,
                                output : html,
                                command : xslt_cmd + [custom_html_xsl, '@INPUT@'],
                                depends : [man_page_depends, p2],
                                install : want_html,
                                install_dir : docdir / 'html')
                        html_pages += p3
                endif
        else
                message('Skipping @0@.@1@ because @2@ is false'.format(stem, section, condition))
        endif
endforeach

############################################################

have_lxml = run_command(xml_helper_py, check: false).returncode() == 0
if not have_lxml
        message('python-lxml not available, not making man page indices')
endif

systemd_directives_xml = custom_target(
        input : ['directives-template.xml', source_xml_files],
        output : 'systemd.directives.xml',
        depends : man_page_depends,
        command : [make_directive_index_py, '@OUTPUT@', '@INPUT@'])

nonindex_xml_files = source_xml_files + [systemd_directives_xml]
systemd_index_xml = custom_target(
        input : nonindex_xml_files,
        output : 'systemd.index.xml',
        command : [make_man_index_py, '@OUTPUT@'] + nonindex_xml_files)

foreach tuple : xsltproc.found() and have_lxml ? [['systemd.directives', '7', systemd_directives_xml],
                                                  ['systemd.index',      '7', systemd_index_xml]] : []
        stem = tuple[0]
        section = tuple[1]
        xml = tuple[2]

        html = stem + '.html'
        man = stem + '.' + section

        mandirn = get_option('mandir') / ('man' + section)

        p1 = custom_target(
                input : xml,
                output : man,
                command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
                install : want_man,
                install_dir : mandirn)
        man_pages += p1

        p2 = []
        if html == 'systemd.index.html'
                htmlalias = 'index.html'
                link = custom_target(
                        input : p2,
                        output : htmlalias,
                        command : [ln, '-fs', html, '@OUTPUT@'])
                if want_html
                        install_symlink(htmlalias,
                                        pointing_to : html,
                                        install_dir : docdir / 'html')
                        p2 += link
                endif
                html_pages += link
        endif

        p3 = custom_target(
                input : xml,
                output : html,
                command : xslt_cmd + [custom_html_xsl, '@INPUT@'],
                depends : [man_page_depends, p2],
                install : want_html,
                install_dir : docdir / 'html')
        html_pages += p3
endforeach

# Cannot use run_target because those targets are used in depends
# Also see https://github.com/mesonbuild/meson/issues/368.
man = custom_target(
        output : 'man',
        depends : man_pages,
        command : [echo])

html = custom_target(
        output : 'html',
        depends : html_pages,
        command : [echo])

if rsync.found()
        run_target(
                'doc-sync',
                depends : man_pages + html_pages,
                command : [sync_docs_py,
                           '--version',
                           '@0@'.format(meson.project_version()),
                           meson.current_build_dir(),
                           get_option('www-target')])
endif

############################################################

buildroot_substs = configuration_data()
buildroot_substs.set_quoted('BUILD_ROOT', meson.project_build_root())

configure_file(
        input : 'man.in',
        output : 'man',
        configuration : buildroot_substs)

configure_file(
        input : 'html.in',
        output : 'html',
        configuration : buildroot_substs)

############################################################

update_dbus_docs = custom_target(
        'update-dbus-docs-impl',
        output : 'update-dbus-docs',
        command : [update_dbus_docs_py, '--build-dir', meson.project_build_root(), '@INPUT@'],
        input : dbus_docs,
        depends : dbus_programs)

if conf.get('BUILD_MODE_DEVELOPER') == 1
        test('dbus-docs-fresh',
             update_dbus_docs_py,
             suite : 'dist',
             args : ['--build-dir', meson.project_build_root(), '--test', dbus_docs],
             depends : dbus_programs)

        test('check-version-history',
             check_version_history_py,
             suite : 'dist',
             args : source_xml_files)
endif

update_man_rules = custom_target(
        'update-man-rules-impl',
        output : 'update-man-rules',
        command : [update_man_rules_py,
                   '@0@/man/*.xml'.format(meson.project_source_root()),
                   '@0@/rules/meson.build'.format(meson.current_source_dir())],
        depends : man_page_depends)

############################################################

simple_examples = files(
        'event-quick-child.c',
        'hwdb-usb-device.c',
        'id128-app-specific.c',
        'inotify-watch-tmp.c',
        'journal-enumerate-fields.c',
        'journal-iterate-foreach.c',
        'journal-iterate-poll.c',
        'journal-iterate-unique.c',
        'journal-iterate-wait.c',
        'journal-stream-fd.c',
        'logcontrol-example.c',
        'notify-selfcontained-example.c',
        'path-documents.c',
        'print-unit-path-call-method.c',
        'print-unit-path.c',
        'sd-bus-container-append.c',
        'sd-bus-container-read.c',
        'sd_bus_error-example.c',
        'sd_bus_service_reconnect.c',
        'sd_device_enumerator_add_match_parent-example.c',
        'sd_device_enumerator_new-example.c',
        'send-unit-files-changed.c',
        'vtable-example.c',
)

examples = []
foreach example : simple_examples
        examples += [ { 'file' : example } ]
endforeach

if conf.get('HAVE_GLIB') == 1
        examples += [
                {
                        'file' : files('glib-event-glue.c'),
                        'opts' : [
                                '-I', libglib.get_variable('includedir') / 'glib-2.0',
                                '-I', libglib.get_variable('libdir') / 'glib-2.0/include',
                        ],
                },
        ]
endif

default_args = [
        cc.cmd_array(),
        '-c',
        '-x', 'c',
        '-pedantic',
        '-Wall',
        '-Werror',
        '-Wextra',
        '-Wno-unused-parameter',
        '-o', '/dev/null',
        '-I', meson.current_source_dir() / '../src',
]

std_args_in = [
        [ '-std=c90', '-Wno-pedantic', '-Wno-variadic-macros', ],
        [ '-std=c99', ],
        [ '-std=c11', ],
        [ '-std=c17', ],
        [ '-std=c23', ],
        [ '-std=gnu90', '-Wno-pedantic', '-Wno-variadic-macros', ],
        [ '-std=gnu99', ],
        [ '-std=gnu11', ],
        [ '-std=gnu17', ],
        [ '-std=gnu23', ],
]

std_args = []
foreach std : std_args_in
        if cc.has_argument(std[0])
                std_args += [std]
        endif
endforeach

foreach item : examples
        foreach std : std_args
                file = item.get('file')
                test('cc-' + fs.stem(file) + '-' + std[0].split('=')[1],
                     env,
                     suite : 'example',
                     args : default_args + std + item.get('opts', []) + [file])
        endforeach
endforeach
