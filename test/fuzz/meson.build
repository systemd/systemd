# SPDX-License-Identifier: LGPL-2.1-or-later

# The 'optimization' option was introduced in meson 0.48.0, so let's keep
# the code compatible with older versions as well
if meson.version().version_compare('>=0.48.0')
        optimization = '--optimization=@0@'.format(get_option('optimization'))
else
        optimization = ''
endif

sanitize_address_undefined = custom_target(
        'sanitize-address-undefined-fuzzers',
        output : 'sanitize-address-undefined-fuzzers',
        command : [meson_build_sh,
                   project_source_root,
                   '@OUTPUT@',
                   'fuzzers',
                   '-Dfuzz-tests=true -Db_lundef=false -Db_sanitize=address,undefined @0@'.format(optimization),
                   ' '.join(cc.cmd_array()),
                   cxx_cmd])

sanitizers = [['address,undefined', sanitize_address_undefined]]

if git.found()
        out = run_command(
                'env', '-u', 'GIT_WORK_TREE',
                git,
                '--git-dir=@0@/.git'.format(project_source_root),
                'ls-files', ':/test/fuzz/*/*')
else
        out = run_command(
                'sh', '-c', 'ls @0@/test/fuzz/*/*'.format(project_source_root))
endif

fuzz_regression_tests = []
foreach p : out.stdout().split()
        # Remove the last entry which is ''.
        #
        # Also, backslashes get mangled, so skip test. See
        # https://github.com/mesonbuild/meson/issues/1564.
        if not p.contains('\\')
                fuzz_regression_tests += p
        endif
endforeach
