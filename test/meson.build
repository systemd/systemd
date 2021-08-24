# SPDX-License-Identifier: LGPL-2.1-or-later

if install_tests
        testdata_dir = testsdir + '/testdata/'

        install_subdir('journal-data',
                       install_dir : testdata_dir)
        install_subdir('units',
                       install_dir : testdata_dir)
        install_subdir('test-execute',
                       install_dir : testdata_dir)
        install_subdir('test-path',
                       install_dir : testdata_dir)
        install_subdir('test-path-util',
                       install_dir : testdata_dir)
        install_subdir('test-umount',
                       install_dir : testdata_dir)
        install_subdir('test-network-generator-conversion',
                       install_dir : testdata_dir)
        install_subdir('testsuite-04.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-06.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-10.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-11.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-16.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-28.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-30.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-52.units',
                       install_dir : testdata_dir)
        install_subdir('testsuite-63.units',
                       install_dir : testdata_dir)

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

        if conf.get('ENABLE_RESOLVE') == 1
                install_subdir('test-resolve',
                               install_dir : testdata_dir)
        endif

        install_data('create-busybox-container',
                     install_mode : 'rwxr-xr-x',
                     install_dir : testdata_dir)
endif

test_network_generator_conversion_sh = find_program('test-network-generator-conversion.sh')
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
                       install_dir : testdata_dir)
endif

############################################################

rule_syntax_check_py = find_program('rule-syntax-check.py')
if want_tests != 'false'
        test('rule-syntax-check',
             rule_syntax_check_py,
             args : all_rules)
endif

############################################################

if conf.get('HAVE_SYSV_COMPAT') == 1
        sysv_generator_test_py = find_program('sysv-generator-test.py')
        if want_tests != 'false'
                test('sysv-generator-test',
                     sysv_generator_test_py)
        endif
endif

############################################################

if install_tests
        install_data('run-unit-tests.py',
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

if want_tests != 'false' and dmi_arches.contains(host_machine.cpu_family())
        udev_dmi_memory_id_test = find_program('udev-dmi-memory-id-test.sh')

        if git.found()
                out = run_command(
                        env, '-u', 'GIT_WORK_TREE',
                        git, '--git-dir=@0@/.git'.format(project_source_root),
                        'ls-files', ':/test/dmidecode-dumps/*.bin')
        else
                out = run_command(
                        sh, '-c', 'ls @0@/test/dmidecode-dumps/*.bin'.format(project_source_root))
        endif

        foreach p : out.stdout().split()
                source = join_paths(project_source_root, p)
                name = 'dmidecode_' + p.split('/')[-1].split('.')[0]

                test(name,
                     udev_dmi_memory_id_test,
                     args : [dmi_memory_id_path, source, source + '.txt'])
        endforeach
endif

subdir('fuzz')
