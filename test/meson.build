# SPDX-License-Identifier: LGPL-2.1-or-later

if install_tests
        testdata_dir = testsdir + '/testdata/'

        install_subdir('journal-data',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('test-execute',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('test-fstab-generator',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('test-path',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('test-path-util',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('test-umount',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('test-network-generator-conversion',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-03.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-04.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-06.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-10.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-11.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-16.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-28.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-30.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-52.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
        install_subdir('testsuite-63.units',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)

        install_data(kbd_model_map,
                     install_dir : testdata_dir + '/test-keymap-util')

        testsuite08_dir = testdata_dir + '/testsuite-08.units'
        install_data('testsuite-08.units/-.mount',
                     install_dir : testsuite08_dir)
        install_data('testsuite-08.units/systemd-remount-fs.service',
                     install_dir : testsuite08_dir)
        meson.add_install_script(meson_make_symlink,
                                 './-.mount',
                                 testsuite08_dir + '/root.mount')
        meson.add_install_script(meson_make_symlink,
                                 '../-.mount',
                                 testsuite08_dir + '/local-fs.target.wants/-.mount')

        if conf.get('HAVE_GNU_EFI') == 1 and conf.get('HAVE_ZSTD') == 1
                install_subdir('test-bcd',
                               exclude_files : '.gitattributes',
                               install_dir : testdata_dir)
        endif
        if conf.get('ENABLE_RESOLVE') == 1
                install_subdir('test-resolve',
                               exclude_files : '.gitattributes',
                               install_dir : testdata_dir)
        endif

        install_data('create-busybox-container',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testdata_dir)
endif

test_fstab_generator_sh = find_program('test-fstab-generator.sh')
test_network_generator_conversion_sh = find_program('test-network-generator-conversion.sh')
test_systemctl_enable_sh = find_program('test-systemctl-enable.sh')
test_systemd_tmpfiles_py = find_program('test-systemd-tmpfiles.py')
hwdb_test_sh = find_program('hwdb-test.sh')

############################################################

test_sysusers_sh = configure_file(
        input : 'test-sysusers.sh.in',
        output : 'test-sysusers.sh',
        configuration : conf)
if install_tests and conf.get('ENABLE_SYSUSERS') == 1
        install_data(test_sysusers_sh,
                     install_dir : testsdir)
        install_subdir('test-sysusers',
                       exclude_files : '.gitattributes',
                       install_dir : testdata_dir)
endif

############################################################

test_compare_versions_sh = files('test-compare-versions.sh')
if install_tests
        install_data(test_compare_versions_sh,
                     install_dir : testsdir)
endif

############################################################

rule_syntax_check_py = find_program('rule-syntax-check.py')
if want_tests != 'false'
        test('rule-syntax-check',
             rule_syntax_check_py,
             suite : 'dist-check',
             args : all_rules)
endif

############################################################

if install_tests
        install_data('run-unit-tests.py',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testsdir)

        install_data('test-fstab-generator.sh',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testsdir)

        install_data('test-network-generator-conversion.sh',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testsdir)
endif

############################################################

# prepare test/sys tree
sys_script_py = find_program('sys-script.py')
custom_target(
        'sys',
        command : [sys_script_py, meson.current_build_dir()],
        output : 'sys',
        build_by_default : want_tests != 'false')

if perl.found()
        udev_test_pl = find_program('udev-test.pl')
        if want_tests != 'false'
                test('udev-test',
                     udev_test_pl,
                     timeout : 180)
        endif
else
        message('Skipping udev-test because perl is not available')
endif

############################################################

rpm = find_program('rpm', required : false)
rpmspec = find_program('rpmspec', required : false)
test_rpm_macros = find_program('test-rpm-macros.sh')

if rpm.found() and rpmspec.found()
        if want_tests != 'false'
                test('test-rpm-macros',
                     test_rpm_macros,
                     suite : 'dist-check',
                     args : [project_build_root])
        endif
else
      message('Skipping test-rpm-macros since rpm and/or rpmspec are not available')
endif

############################################################

if want_tests != 'false' and dmi_arches.contains(host_machine.cpu_family())
        udev_dmi_memory_id_test = find_program('udev-dmi-memory-id-test.sh')

        if git.found() and fs.exists(project_source_root / '.git')
                out = run_command(
                        env, '-u', 'GIT_WORK_TREE',
                        git, '--git-dir=@0@/.git'.format(project_source_root),
                        'ls-files', ':/test/dmidecode-dumps/*.bin',
                        check: true)
        else
                out = run_command(
                        sh, '-c', 'cd "$1"; echo test/dmidecode-dumps/*.bin', '_', project_source_root,
                        check: true)
        endif

        foreach p : out.stdout().split()
                source = project_source_root / p
                name = 'dmidecode_' + p.split('/')[-1].split('.')[0]

                test(name,
                     udev_dmi_memory_id_test,
                     suite : 'dist-check',
                     args : [udev_prog_paths['dmi_memory_id'].full_path(),
                             source,
                             source + '.txt'],
                     depends : udev_prog_paths['dmi_memory_id'])
        endforeach
endif

subdir('fuzz')
