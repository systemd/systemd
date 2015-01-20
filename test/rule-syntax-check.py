# Simple udev rules syntax checker
#
# (C) 2010 Canonical Ltd.
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

import re
import sys
import os
from glob import glob

if len(sys.argv) > 1:
    # explicit rule file list
    rules_files = sys.argv[1:]
else:
    # take them from the build dir
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(os.environ.get('top_srcdir', root_dir), 'rules')
    if not os.path.isdir(rules_dir):
        sys.stderr.write('No rules files given, and %s does not exist, aborting' % rules_dir)
        sys.exit(2)
    rules_files = glob(os.path.join(rules_dir, '*.rules'))

no_args_tests = re.compile('(ACTION|DEVPATH|KERNELS?|NAME|SYMLINK|SUBSYSTEMS?|DRIVERS?|TAG|RESULT|TEST)\s*(?:=|!)=\s*"([^"]*)"$')
args_tests = re.compile('(ATTRS?|ENV|TEST){([a-zA-Z0-9/_.*%-]+)}\s*(?:=|!)=\s*"([^"]*)"$')
no_args_assign = re.compile('(NAME|SYMLINK|OWNER|GROUP|MODE|TAG|PROGRAM|RUN|LABEL|GOTO|WAIT_FOR|OPTIONS|IMPORT)\s*(?:\+=|:=|=)\s*"([^"]*)"$')
args_assign = re.compile('(ATTR|ENV|IMPORT|RUN){([a-zA-Z0-9/_.*%-]+)}\s*(=|\+=)\s*"([^"]*)"$')

result = 0
buffer = ''
for path in rules_files:
    lineno = 0
    for line in open(path):
        lineno += 1

        # handle line continuation
        if line.endswith('\\\n'):
            buffer += line[:-2]
            continue
        else:
            line = buffer + line
            buffer = ''

        # filter out comments and empty lines
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        for clause in line.split(','):
            clause = clause.strip()
            if not (no_args_tests.match(clause) or args_tests.match(clause) or
                    no_args_assign.match(clause) or args_assign.match(clause)):

                print('Invalid line %s:%i: %s' % (path, lineno, line))
                print('  clause: %s' % clause)
                print('')
                result = 1
                break

sys.exit(result)
