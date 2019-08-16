# SPDX-License-Identifier: LGPL-2.1+

# This is lame, I know, but meson has no other include mechanism
subdir('rules')

want_man = get_option('man')
want_html = get_option('html')
xsltproc = find_program('xsltproc',
                        required : want_man == 'true' or want_html == 'true')
want_man = want_man != 'false' and xsltproc.found()
want_html = want_html != 'false' and xsltproc.found()

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
        '@0@:@1@'.format(meson.current_build_dir(), meson.current_source_dir())]

custom_man_xsl = files('custom-man.xsl')
custom_html_xsl = files('custom-html.xsl')
xslt_cmd = [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags

custom_entities_ent = configure_file(
        input : 'custom-entities.ent.in',
        output : 'custom-entities.ent',
        configuration : conf)

man_pages = []
html_pages = []
source_xml_files = []
foreach tuple : xsltproc.found() ? manpages : []
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

        mandirn = join_paths(get_option('mandir'), 'man' + section)

        if condition == '' or conf.get(condition) == 1
                p1 = custom_target(
                        man,
                        input : xml,
                        output : [man] + manaliases,
                        command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
                        depend_files : custom_entities_ent,
                        install : want_man,
                        install_dir : mandirn)
                man_pages += p1

                p2 = []
                foreach htmlalias : htmlaliases
                        link = custom_target(
                                htmlalias,
                                input : p2,
                                output : htmlalias,
                                command : ['ln', '-fs', html, '@OUTPUT@'])
                        if want_html
                                dst = join_paths(docdir, 'html', htmlalias)
                                cmd = 'ln -fs @0@ $DESTDIR@1@'.format(html, dst)
                                meson.add_install_script('sh', '-c', cmd)
                                p2 += link
                        endif
                        html_pages += link
                endforeach

                p3 = custom_target(
                        html,
                        input : xml,
                        output : html,
                        command : xslt_cmd + [custom_html_xsl, '@INPUT@'],
                        depend_files : custom_entities_ent,
                        depends : p2,
                        install : want_html,
                        install_dir : join_paths(docdir, 'html'))
                html_pages += p3

                source_xml_files += files(tuple[0] + '.xml')
        else
                message('Skipping @0@.@1@ because @2@ is false'.format(stem, section, condition))
        endif
endforeach

############################################################

have_lxml = run_command(xml_helper_py).returncode() == 0
if not have_lxml
        message('python-lxml not available, not making man page indices')
endif

systemd_directives_xml = custom_target(
        'systemd.directives.xml',
        input : source_xml_files,
        output : 'systemd.directives.xml',
        command : [make_directive_index_py, '@OUTPUT@'] + source_xml_files)

nonindex_xml_files = source_xml_files + [systemd_directives_xml]
systemd_index_xml = custom_target(
        'systemd.index.xml',
        input : nonindex_xml_files,
        output : 'systemd.index.xml',
        command : [make_man_index_py, '@OUTPUT@'] + nonindex_xml_files)

foreach tuple : xsltproc.found() ? [['systemd.directives', '7', systemd_directives_xml],
                                    ['systemd.index',      '7', systemd_index_xml]] : []
        stem = tuple[0]
        section = tuple[1]
        xml = tuple[2]

        html = stem + '.html'
        man = stem + '.' + section

        mandirn = join_paths(get_option('mandir'), 'man' + section)

        p1 = custom_target(
                man,
                input : xml,
                output : man,
                command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
                install : want_man and have_lxml,
                install_dir : mandirn)
        man_pages += p1

        p2 = []
        if html == 'systemd.index.html'
                htmlalias = 'index.html'
                link = custom_target(
                        htmlalias,
                        input : p2,
                        output : htmlalias,
                        command : ['ln', '-fs', html, '@OUTPUT@'])
                if want_html
                        dst = join_paths(docdir, 'html', htmlalias)
                        cmd = 'ln -fs @0@ $DESTDIR@1@'.format(html, dst)
                        meson.add_install_script('sh', '-c', cmd)
                        p2 += link
                endif
                html_pages += link
        endif

        p3 = custom_target(
                html,
                input : xml,
                output : html,
                command : xslt_cmd + [custom_html_xsl, '@INPUT@'],
                depend_files : custom_entities_ent,
                depends : p2,
                install : want_html and have_lxml,
                install_dir : join_paths(docdir, 'html'))
        html_pages += p3
endforeach

# Cannot use run_target because those targets are used in depends
# Also see https://github.com/mesonbuild/meson/issues/368.
man = custom_target(
        'man',
        output : 'man',
        depends : man_pages,
        command : ['echo'])

html = custom_target(
        'html',
        output : 'html',
        depends : html_pages,
        command : ['echo'])

run_target(
        'doc-sync',
        depends : man_pages + html_pages,
        command : ['rsync', '-rlv',
                   '--delete-excluded',
                   '--include=man',
                   '--include=*.html',
                   '--exclude=*',
                   '--omit-dir-times',
                   meson.current_build_dir(),
                   get_option('www-target')])

############################################################

if git.found()
        custom_target(
                'update-man-rules',
                output : 'update-man-rules',
                command : ['sh', '-c',
                           'cd @0@ && '.format(meson.build_root()) +
                           'python3 @0@/tools/make-man-rules.py $(git ls-files ":/man/*.xml") >t && '.format(project_source_root) +
                           'mv t @0@/rules/meson.build'.format(meson.current_source_dir())],
                depend_files : custom_entities_ent)
endif

############################################################

configure_file(
        input : 'man.in',
        output : 'man',
        configuration : substs)

configure_file(
        input : 'html.in',
        output : 'html',
        configuration : substs)
