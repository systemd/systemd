# systemd-sysv-generator integration test
#
# (C) 2015 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

import unittest
import sys
import os
import subprocess
import tempfile
import shutil
from glob import glob

try:
    from configparser import RawConfigParser
except ImportError:
    # python 2
    from ConfigParser import RawConfigParser

sysv_generator = os.path.join(os.environ.get('builddir', '.'), 'systemd-sysv-generator')


class SysvGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix='sysv-gen-test.')
        self.init_d_dir = os.path.join(self.workdir, 'init.d')
        os.mkdir(self.init_d_dir)
        self.rcnd_dir = self.workdir
        self.unit_dir = os.path.join(self.workdir, 'systemd')
        os.mkdir(self.unit_dir)
        self.out_dir = os.path.join(self.workdir, 'output')
        os.mkdir(self.out_dir)

    def tearDown(self):
        shutil.rmtree(self.workdir)

    #
    # Helper methods
    #

    def run_generator(self, expect_error=False):
        '''Run sysv-generator.

        Fail if stderr contains any "Fail", unless expect_error is True.
        Return (stderr, filename -> ConfigParser) pair with ouput to stderr and
        parsed generated units.
        '''
        env = os.environ.copy()
        env['SYSTEMD_LOG_LEVEL'] = 'debug'
        env['SYSTEMD_LOG_TARGET'] = 'console'
        env['SYSTEMD_SYSVINIT_PATH'] = self.init_d_dir
        env['SYSTEMD_SYSVRCND_PATH'] = self.rcnd_dir
        env['SYSTEMD_UNIT_PATH'] = self.unit_dir
        gen = subprocess.Popen(
            [sysv_generator, 'ignored', 'ignored', self.out_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, env=env)
        (out, err) = gen.communicate()
        if not expect_error:
            self.assertFalse('Fail' in err, err)
        self.assertEqual(gen.returncode, 0, err)

        results = {}
        for service in glob(self.out_dir + '/*.service'):
            if os.path.islink(service):
                continue
            cp = RawConfigParser()
            cp.optionxform = lambda o: o  # don't lower-case option names
            with open(service) as f:
                cp.readfp(f)
            results[os.path.basename(service)] = cp

        return (err, results)

    def add_sysv(self, fname, keys, enable=False, prio=1):
        '''Create a SysV init script with the given keys in the LSB header

        There are sensible default values for all fields.
        If enable is True, links will be created in the rcN.d dirs. In that
        case, the priority can be given with "prio" (default to 1).

        Return path of generated script.
        '''
        name_without_sh = fname.endswith('.sh') and fname[:-3] or fname
        keys.setdefault('Provides', name_without_sh)
        keys.setdefault('Required-Start', '$local_fs')
        keys.setdefault('Required-Stop', keys['Required-Start'])
        keys.setdefault('Default-Start', '2 3 4 5')
        keys.setdefault('Default-Stop', '0 1 6')
        keys.setdefault('Short-Description', 'test %s service' %
                        name_without_sh)
        keys.setdefault('Description', 'long description for test %s service' %
                        name_without_sh)
        script = os.path.join(self.init_d_dir, fname)
        with open(script, 'w') as f:
            f.write('#!/bin/init-d-interpreter\n### BEGIN INIT INFO\n')
            for k, v in keys.items():
                if v is not None:
                    f.write('#%20s %s\n' % (k + ':', v))
            f.write('### END INIT INFO\ncode --goes here\n')
        os.chmod(script, 0o755)

        if enable:
            def make_link(prefix, runlevel):
                d = os.path.join(self.rcnd_dir, 'rc%s.d' % runlevel)
                if not os.path.isdir(d):
                    os.mkdir(d)
                os.symlink('../init.d/' + fname, os.path.join(d, prefix + fname))

            for rl in keys['Default-Start'].split():
                make_link('S%02i' % prio, rl)
            for rl in keys['Default-Stop'].split():
                make_link('K%02i' % (99 - prio), rl)

        return script

    def assert_enabled(self, unit, targets):
        '''assert that a unit is enabled in precisely the given targets'''

        all_targets = ['multi-user', 'graphical']

        # should be enabled
        for target in all_targets:
            link = os.path.join(self.out_dir, '%s.target.wants' % target, unit)
            if target in targets:
                unit_file = os.readlink(link)
                self.assertTrue(os.path.exists(unit_file))
                self.assertEqual(os.path.basename(unit_file), unit)
            else:
                self.assertFalse(os.path.exists(link),
                                 '%s unexpectedly exists' % link)

    #
    # test cases
    #

    def test_nothing(self):
        '''no input files'''

        results = self.run_generator()[1]
        self.assertEqual(results, {})
        self.assertEqual(os.listdir(self.out_dir), [])

    def test_simple_disabled(self):
        '''simple service without dependencies, disabled'''

        self.add_sysv('foo', {}, enable=False)
        err, results = self.run_generator()
        self.assertEqual(len(results), 1)

        # no enablement links or other stuff
        self.assertEqual(os.listdir(self.out_dir), ['foo.service'])

        s = results['foo.service']
        self.assertEqual(s.sections(), ['Unit', 'Service'])
        self.assertEqual(s.get('Unit', 'Description'), 'LSB: test foo service')
        # $local_fs does not need translation, don't expect any dependency
        # fields here
        self.assertEqual(set(s.options('Unit')),
                         set(['Documentation', 'SourcePath', 'Description']))

        self.assertEqual(s.get('Service', 'Type'), 'forking')
        init_script = os.path.join(self.init_d_dir, 'foo')
        self.assertEqual(s.get('Service', 'ExecStart'),
                         '%s start' % init_script)
        self.assertEqual(s.get('Service', 'ExecStop'),
                         '%s stop' % init_script)

        self.assertNotIn('Overwriting', err)

    def test_simple_enabled_all(self):
        '''simple service without dependencies, enabled in all runlevels'''

        self.add_sysv('foo', {}, enable=True)
        err, results = self.run_generator()
        self.assertEqual(list(results), ['foo.service'])
        self.assert_enabled('foo.service', ['multi-user', 'graphical'])
        self.assertNotIn('Overwriting', err)

    def test_simple_escaped(self):
        '''simple service without dependencies, that requires escaping the name'''

        self.add_sysv('foo+', {})
        self.add_sysv('foo-admin', {})
        err, results = self.run_generator()
        self.assertEqual(set(results), {'foo-admin.service', 'foo\\x2b.service'})
        self.assertNotIn('Overwriting', err)

    def test_simple_enabled_some(self):
        '''simple service without dependencies, enabled in some runlevels'''

        self.add_sysv('foo', {'Default-Start': '2 4'}, enable=True)
        err, results = self.run_generator()
        self.assertEqual(list(results), ['foo.service'])
        self.assert_enabled('foo.service', ['multi-user'])

    def test_lsb_macro_dep_single(self):
        '''single LSB macro dependency: $network'''

        self.add_sysv('foo', {'Required-Start': '$network'})
        s = self.run_generator()[1]['foo.service']
        self.assertEqual(set(s.options('Unit')),
                         set(['Documentation', 'SourcePath', 'Description', 'After', 'Wants']))
        self.assertEqual(s.get('Unit', 'After'), 'network-online.target')
        self.assertEqual(s.get('Unit', 'Wants'), 'network-online.target')

    def test_lsb_macro_dep_multi(self):
        '''multiple LSB macro dependencies'''

        self.add_sysv('foo', {'Required-Start': '$named $portmap'})
        s = self.run_generator()[1]['foo.service']
        self.assertEqual(set(s.options('Unit')),
                         set(['Documentation', 'SourcePath', 'Description', 'After']))
        self.assertEqual(s.get('Unit', 'After'), 'nss-lookup.target rpcbind.target')

    def test_lsb_deps(self):
        '''LSB header dependencies to other services'''

        # also give symlink priorities here; they should be ignored
        self.add_sysv('foo', {'Required-Start': 'must1 must2',
                              'Should-Start': 'may1 ne_may2'},
                      enable=True, prio=40)
        self.add_sysv('must1', {}, enable=True, prio=10)
        self.add_sysv('must2', {}, enable=True, prio=15)
        self.add_sysv('may1', {}, enable=True, prio=20)
        # do not create ne_may2
        err, results = self.run_generator()
        self.assertEqual(sorted(results),
                         ['foo.service', 'may1.service', 'must1.service', 'must2.service'])

        # foo should depend on all of them
        self.assertEqual(sorted(results['foo.service'].get('Unit', 'After').split()),
                         ['may1.service', 'must1.service', 'must2.service', 'ne_may2.service'])

        # other services should not depend on each other
        self.assertFalse(results['must1.service'].has_option('Unit', 'After'))
        self.assertFalse(results['must2.service'].has_option('Unit', 'After'))
        self.assertFalse(results['may1.service'].has_option('Unit', 'After'))

    def test_symlink_prio_deps(self):
        '''script without LSB headers use rcN.d priority'''

        # create two init.d scripts without LSB header and enable them with
        # startup priorities
        for prio, name in [(10, 'provider'), (15, 'consumer')]:
            with open(os.path.join(self.init_d_dir, name), 'w') as f:
                f.write('#!/bin/init-d-interpreter\ncode --goes here\n')
                os.fchmod(f.fileno(), 0o755)

            d = os.path.join(self.rcnd_dir, 'rc2.d')
            if not os.path.isdir(d):
                os.mkdir(d)
            os.symlink('../init.d/' + name, os.path.join(d, 'S%02i%s' % (prio, name)))

        err, results = self.run_generator()
        self.assertEqual(sorted(results), ['consumer.service', 'provider.service'])
        self.assertFalse(results['provider.service'].has_option('Unit', 'After'))
        self.assertEqual(results['consumer.service'].get('Unit', 'After'),
                         'provider.service')

    def test_multiple_provides(self):
        '''multiple Provides: names'''

        self.add_sysv('foo', {'Provides': 'foo bar baz'})
        err, results = self.run_generator()
        self.assertEqual(list(results), ['foo.service'])
        self.assertEqual(set(results['foo.service'].options('Unit')),
                         set(['Documentation', 'SourcePath', 'Description']))
        # should create symlinks for the alternative names
        for f in ['bar.service', 'baz.service']:
            self.assertEqual(os.readlink(os.path.join(self.out_dir, f)),
                             'foo.service')
        self.assertNotIn('Overwriting', err)

    def test_provides_escaped(self):
        '''a script that Provides: a name that requires escaping'''

        self.add_sysv('foo', {'Provides': 'foo foo+'})
        err, results = self.run_generator()
        self.assertEqual(list(results), ['foo.service'])
        self.assertEqual(os.readlink(os.path.join(self.out_dir, 'foo\\x2b.service')),
                'foo.service')
        self.assertNotIn('Overwriting', err)

    def test_same_provides_in_multiple_scripts(self):
        '''multiple init.d scripts provide the same name'''

        self.add_sysv('foo', {'Provides': 'foo common'}, enable=True, prio=1)
        self.add_sysv('bar', {'Provides': 'bar common'}, enable=True, prio=2)
        err, results = self.run_generator()
        self.assertEqual(sorted(results), ['bar.service', 'foo.service'])
        # should create symlink for the alternative name for either unit
        self.assertIn(os.readlink(os.path.join(self.out_dir, 'common.service')),
                      ['foo.service', 'bar.service'])

    def test_provide_other_script(self):
        '''init.d scripts provides the name of another init.d script'''

        self.add_sysv('foo', {'Provides': 'foo bar'}, enable=True)
        self.add_sysv('bar', {'Provides': 'bar'}, enable=True)
        err, results = self.run_generator()
        self.assertEqual(sorted(results), ['bar.service', 'foo.service'])
        # we do expect an overwrite here, bar.service should overwrite the
        # alias link from foo.service
        self.assertIn('Overwriting', err)

    def test_nonexecutable_script(self):
        '''ignores non-executable init.d script'''

        os.chmod(self.add_sysv('foo', {}), 0o644)
        err, results = self.run_generator()
        self.assertEqual(results, {})

    def test_sh_suffix(self):
        '''init.d script with .sh suffix'''

        self.add_sysv('foo.sh', {}, enable=True)
        err, results = self.run_generator()
        s = results['foo.service']

        self.assertEqual(s.sections(), ['Unit', 'Service'])
        # should not have a .sh
        self.assertEqual(s.get('Unit', 'Description'), 'LSB: test foo service')

        # calls correct script with .sh
        init_script = os.path.join(self.init_d_dir, 'foo.sh')
        self.assertEqual(s.get('Service', 'ExecStart'),
                         '%s start' % init_script)
        self.assertEqual(s.get('Service', 'ExecStop'),
                         '%s stop' % init_script)

        self.assert_enabled('foo.service', ['multi-user', 'graphical'])

    def test_sh_suffix_with_provides(self):
        '''init.d script with .sh suffix and Provides:'''

        self.add_sysv('foo.sh', {'Provides': 'foo bar'})
        err, results = self.run_generator()
        # ensure we don't try to create a symlink to itself
        self.assertNotIn('itself', err)
        self.assertEqual(list(results), ['foo.service'])
        self.assertEqual(results['foo.service'].get('Unit', 'Description'),
                         'LSB: test foo service')

        # should create symlink for the alternative name
        self.assertEqual(os.readlink(os.path.join(self.out_dir, 'bar.service')),
                         'foo.service')

    def test_hidden_files(self):
        '''init.d script with hidden file suffix'''

        script = self.add_sysv('foo', {}, enable=True)
        # backup files (not enabled in rcN.d/)
        shutil.copy(script, script + '.dpkg-new')
        shutil.copy(script, script + '.dpkg-dist')
        shutil.copy(script, script + '.swp')
        shutil.copy(script, script + '.rpmsave')

        err, results = self.run_generator()
        self.assertEqual(list(results), ['foo.service'])

        self.assert_enabled('foo.service', ['multi-user', 'graphical'])

    def test_backup_file(self):
        '''init.d script with backup file'''

        script = self.add_sysv('foo', {}, enable=True)
        # backup files (not enabled in rcN.d/)
        shutil.copy(script, script + '.bak')
        shutil.copy(script, script + '.old')

        err, results = self.run_generator()
        print(err)
        self.assertEqual(sorted(results),
                         ['foo.bak.service', 'foo.old.service', 'foo.service'])

        # ensure we don't try to create a symlink to itself
        self.assertNotIn('itself', err)

        self.assert_enabled('foo.service', ['multi-user', 'graphical'])
        self.assert_enabled('foo.bak.service', [])
        self.assert_enabled('foo.old.service', [])

    def test_existing_native_unit(self):
        '''existing native unit'''

        with open(os.path.join(self.unit_dir, 'foo.service'), 'w') as f:
            f.write('[Unit]\n')

        self.add_sysv('foo.sh', {'Provides': 'foo bar'}, enable=True)
        err, results = self.run_generator()
        self.assertEqual(list(results), [])
        # no enablement or alias links, as native unit is disabled
        self.assertEqual(os.listdir(self.out_dir), [])


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))
