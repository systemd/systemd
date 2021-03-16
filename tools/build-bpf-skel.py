#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

import argparse
import logging
import pathlib
import shutil
import subprocess
import sys

def clang_arch_flag(arch):
    return '-D__{}__'.format(arch)


def target_triplet():
    gcc_exec = None
    try:
        gcc_exec = shutil.which('gcc')
    except shutil.Error as e:
        logging.error('Failed to get which gcc: {}'.format(e))
        return None

    try:
        return subprocess.check_output([gcc_exec, '-dumpmachine'],
                text=True).strip()
    except subprocess.CalledProcessError as e:
        logging.error('Failed to get target triplet: {}'.format(e))
        return None


def clang_compile(clang_exec, clang_flags, src_c, out_file, target_arch,
        target_triplet):
    clang_args = [clang_exec]
    clang_args.extend(clang_flags)
    clang_args.extend([target_arch])

    clang_args.extend([
        '-I.'])

    if target_triplet:
        clang_args.extend([
            '-isystem',
            '/usr/include/{}'.format(target_triplet)])

    clang_args.extend([
        '-idirafter',
        '/usr/local/include',
        '-idirafter',
        '/usr/include'])

    clang_args.extend([src_c])
    clang_args.extend(['-o', out_file])

    logging.debug('Generating ELF object file:')
    logging.debug('{}'.format(' '.join(clang_args)))
    subprocess.check_call(clang_args)


def llvm_strip(llvm_strip_exec, in_file):
    llvm_strip_args = [llvm_strip_exec, '-g', in_file]

    logging.debug('Stripping useless DWARF info:')
    logging.debug('{}'.format(' '.join(llvm_strip_args)))

    subprocess.check_call(llvm_strip_args)


def gen_bpf_skeleton(bpftool_exec, in_file, out_fd):
    bpftool_args = [bpftool_exec]
    bpftool_args.extend(['g', 's'])
    bpftool_args.extend([in_file])

    logging.debug('Generating BPF skeleton:')
    logging.debug('{}'.format(' '.join(bpftool_args)))
    subprocess.check_call(bpftool_args, stdout=out_fd)


def bpf_build(args):
    clang_flags = [
            '-Wno-compare-distinct-pointer-types',
            '-O2',
            '-target',
            'bpf',
            '-g',
            '-c',
    ]

    with open('.'.join([pathlib.Path(args.bpf_src_c).stem, 'o']), mode='w') as clang_out_fd, \
            open(args.bpf_skel_h, mode='w') as bpf_skel_h_fd:
        clang_compile(clang_exec=args.clang_exec,
                clang_flags=clang_flags,
                src_c=args.bpf_src_c,
                out_file=clang_out_fd.name,
                target_arch=clang_arch_flag(args.arch),
                target_triplet=target_triplet())

        llvm_strip(llvm_strip_exec=args.llvm_strip_exec, in_file=clang_out_fd.name)

        gen_bpf_skeleton(bpftool_exec=args.bpftool_exec,
                in_file=clang_out_fd.name,
                out_fd=bpf_skel_h_fd)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
            'bpf_src_c',
            type=str,
            help='Path to *.c source of BPF program in systemd source tree \
                    relative to the work directory.')

    parser.add_argument(
            'bpf_skel_h',
            type=str,
            help='Path to C header file.')

    parser.add_argument(
            '--clang_exec',
            type=str,
            help='Path to clang exec.')

    parser.add_argument(
            '--llvm_strip_exec',
            type=str,
            help='Path to llvm-strip exec.')

    parser.add_argument(
            '--bpftool_exec',
            type=str,
            help='Path to bpftool exec.')

    parser.add_argument(
            '--arch',
            type=str,
            help='Target CPU architecture.',
            default='x86_64')

    args = parser.parse_args();

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    bpf_build(args)
