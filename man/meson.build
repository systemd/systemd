# -*- mode: meson -*-

# This is lame, I know, but meson has no other include mechanism
subdir('rules')

# TODO: add regeneration rule:
# python3 tools/make-man-rules.py --meson man/*xml > man/rules/meson.build

xsltproc = find_program('xsltproc')
xsltproc_flags = [
  '--nonet',
  '--xinclude',
  '--stringparam', 'man.output.quietly', '1',
  '--stringparam', 'funcsynopsis.style', 'ansi',
  '--stringparam', 'man.authors.section.enabled', '0',
  '--stringparam', 'man.copyright.section.enabled', '0',
  '--stringparam', 'systemd.version', '@0@'.format(meson.project_version()),
  '--path',
  '@0@:@1@'.format(meson.current_build_dir(), meson.current_source_dir())]

custom_man_xsl = files('custom-man.xsl')
custom_html_xsl = files('custom-man.xsl')
custom_entities_ent = files('custom-entities.ent')

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
    manaliases += [alias + '.' + section]
    htmlaliases += [alias + '.html']
  endforeach

  mandirn = get_option('mandir') + '/man' + section

  install = condition == '' or conf.get(condition, 0) == 1

  custom_target(
      man,
      input : xml,
      output : [man] + manaliases,
      command : [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags + [custom_man_xsl, '@INPUT@'],
      install : install,
      install_dir : mandirn)

  custom_target(
      html,
      input : xml,
      output : [html] + htmlaliases,
      command : [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags + [custom_html_xsl, '@INPUT@'])

  if not install
    message('Skipping @0@.@1@ because @2@ is @3@'.format(stem, section, condition, install))
  endif
endforeach

############################################################

source_xml_files = files()
foreach tuple : manpages
  source_xml_files += files(tuple[0] + '.xml')
endforeach

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

foreach tuple : [['systemd.directives', '7', systemd_directives_xml],
                 ['systemd.index',      '7', systemd_index_xml]]
  stem = tuple[0]
  section = tuple[1]
  xml = tuple[2]

  html = stem + '.html'
  man = stem + '.' + section

  mandirn = get_option('mandir') + '/man' + section

  custom_target(
      man,
      input : xml,
      output : man,
      command : [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags + [custom_man_xsl, '@INPUT@'],
      install : install,
      install_dir : mandirn)

  custom_target(
      html,
      input : xml,
      output : html,
      command : [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags + [custom_html_xsl, '@INPUT@'])
endforeach
