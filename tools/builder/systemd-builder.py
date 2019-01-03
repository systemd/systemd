#!/usr/bin/python3

import argparse
import os
import pwd
import shlex
import subprocess
import sys

BUILDER_USERNAME = 'builder'
BUILDER_SRC_TREE = '/systemd'
BUILDER_DST_TREE = '/build'

PROGNAME = 'systemd-builder'

class Error(Exception):
    """Error in systemd-builder execution."""

# User management: Functions to create user "builder" and re-run the script
# under that user, if called as "root" for an unprivileged operation. The
# uid/gid of user "builder" are derived from the permissions of the mounted
# destination tree under /build, in order to match uid/gid of user outside of
# the container.

def create_builder_user(uid, gid):
    subprocess.check_call(['groupadd', '-g', str(gid), BUILDER_USERNAME])
    subprocess.check_call(['useradd', '-m', '-u', str(uid), '-g', str(gid), BUILDER_USERNAME])

def reexec_unprivileged(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(os.path.realpath(__file__), sys.argv)

def expected_builder_user_credentials():
    if not os.path.ismount(BUILDER_DST_TREE):
        raise Error('Expected build tree [{}] to be a mount.'.format(BUILDER_DST_TREE))
    st = os.stat(BUILDER_DST_TREE)
    return (st.st_uid, st.st_gid)

def check_builder_user_exists(uid, gid):
    # Returns True if user builder already exists and matches uid/gid.
    # Returns False if user builder (or group) does not exist yet.
    # Raises an Error if user builder exists but does not match uid/gid.
    try:
        pw = pwd.getpwnam(BUILDER_USERNAME)
    except KeyError:
        return False
    if pw.pw_uid != uid or pw.pw_gid != gid:
        raise Error('User {} already exists but does not match expected UID/GID: '
                    'actual {}/{} != expected {}/{}'.format(BUILDER_USERNAME, pw.pw_uid, pw.pw_gid, uid, gid))

def must_run_as_root(cmd):
    if os.geteuid() != 0:
        raise Error('Command {} must run as root.'.format(cmd))

def rerun_as_builder():
    if os.geteuid() != 0:
        # Assume running under correct user if we're running as non-root.
        return
    uid, gid = expected_builder_user_credentials()
    if uid == 0 and gid == 0:
        # In some cases we will build as root. For example, containers running
        # on a hypervisor (such as Docker for Mac) will bind-mount external
        # volumes as root inside the container.
        #
        # Also when we use a scratch volume for the build, the volume has
        # root ownership.
        #
        # This is not ideal, but proceeding here is still a pragmatic solution
        # to handle these issues.
        #
        # Do not reexec_unprivileged in this case.
        return
    if uid < 1000 or gid < 1000:
        raise Error('Build tree UID/GID outside of user range: {}/{}'.format(uid, gid))
    if not check_builder_user_exists(uid, gid):
        create_builder_user(uid, gid)
    reexec_unprivileged(uid, gid)

# Argument parser: Implement subcommands for operations. For now "build" is the
# common one, but we also want to support "setup" for configure the
# systemd-builder container.
#
# This can be further extended with specialized build types, such as
# "cov-build" for Coverity and potentially other specialized build
# configurations.

def create_parser():
    parser = argparse.ArgumentParser(prog=PROGNAME)
    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.add_parser('setup')
    subparsers.add_parser('debugshell')
    build_parser = subparsers.add_parser('build', help='build source tree')
    build_parser.add_argument('--test', action='store_true', help='run ninja tests after building')
    build_parser.add_argument('--meson_args', action='store', help='arguments to pass to meson')
    build_parser.add_argument('--ninja_args', action='store', default='-v', help='arguments to pass to ninja')
    build_parser.add_argument('--test_args', action='store', help='arguments to pass to ninja test')
    return parser

# Subcommands: These implement the actual commands such as "build" and "setup".
# More commands can be added for specialized builders.

def cmd_setup(opts):
    must_run_as_root('setup')
    os.mkdir(BUILDER_SRC_TREE)
    os.mkdir(BUILDER_DST_TREE)

def cmd_debugshell(opts):
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv('/bin/bash', ['-/bin/bash'])

def check_src_tree():
    if not os.path.ismount(BUILDER_SRC_TREE):
        raise Error('Expected source tree [{}] to be a mount.'.format(BUILDER_SRC_TREE))
    # Look for a well-known file in the source tree.
    if not os.path.exists(os.path.join(BUILDER_SRC_TREE, 'src/core/main.c')):
        raise Error('Source tree [{}] does not look like it contains systemd sources.'.format(BUILDER_SRC_TREE))

def cmd_build(opts):
    rerun_as_builder()
    check_src_tree()
    # Assemble the `meson` command-line.
    meson_cmd = ['meson']
    if os.path.exists(os.path.join(BUILDER_DST_TREE, 'build.ninja')):
        # This tree was previously used, so run `meson configure` instead.
        meson_cmd.append('configure')
    meson_cmd.append(BUILDER_DST_TREE)
    meson_cmd.extend(shlex.split(opts.meson_args))
    subprocess.check_call(meson_cmd, cwd=BUILDER_SRC_TREE)
    # Assemble the `ninja` command line.
    ninja_cmd = ['ninja']
    ninja_cmd.extend(shlex.split(opts.ninja_args))
    subprocess.check_call(ninja_cmd, cwd=BUILDER_DST_TREE)
    if opts.test:
        # Assemble the `ninja test` command line.
        test_cmd = ['ninja']
        test_cmd.extend(shlex.split(opts.test_args))
        test_cmd.append('test')
        subprocess.check_call(test_cmd, cwd=BUILDER_DST_TREE)

COMMANDS = {
    'setup': cmd_setup,
    'debugshell': cmd_debugshell,
    'build': cmd_build,
}

def run_main():
    parser = create_parser()
    opts = parser.parse_args()
    if not opts.cmd:
        parser.error('subcommand is required')
    COMMANDS[opts.cmd](opts)

def main(args):
    try:
        run_main()
    except Error as e:
        print('{}: {}'.format(PROGNAME, e), file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print('{}: command [{}] failed with return code {}'.format(
              PROGNAME, ' '.join(shlex.quote(i) for i in e.cmd), e.returncode), file=sys.stderr)
        return e.returncode

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
