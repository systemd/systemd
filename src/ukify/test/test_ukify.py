#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# The tests can be called via pytest:
#   PATH=build/:$PATH pytest -v src/ukify/test/test_ukify.py
# or directly:
#   PATH=build/:$PATH src/ukify/test/test_ukify.py
# or via the meson test machinery output:
#   meson test -C build test-ukify -v
# or without verbose output:
#   meson test -C build test-ukify

# pylint: disable=unused-import,import-outside-toplevel,useless-else-on-loop
# pylint: disable=consider-using-with,wrong-import-position,unspecified-encoding
# pylint: disable=protected-access,redefined-outer-name

import base64
import glob
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace

try:
    import pytest
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

try:
    import pefile
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

# We import ukify.py, which is a template file. But only __version__ is
# substituted, which we don't care about here. Having the .py suffix makes it
# easier to import the file.
sys.path.append(os.path.dirname(__file__) + '/..')
import ukify

# Skip if we're running on an architecture that does not use UEFI.
try:
    ukify.guess_efi_arch()
except ValueError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

build_root = os.getenv('PROJECT_BUILD_ROOT')
try:
    slow_tests = bool(int(os.getenv('SYSTEMD_SLOW_TESTS', '1')))
except ValueError:
    slow_tests = True

arg_tools = ['--tools', build_root] if build_root else []
if (
        build_root
        and (p := pathlib.Path(f'{build_root}/linux{ukify.guess_efi_arch()}.efi.stub')).exists()
):  # fmt: skip
    arg_tools += ['--stub', p]


def systemd_measure():
    opts = ukify.create_parser().parse_args(arg_tools)
    return ukify.find_tool('systemd-measure', opts=opts)


def test_guess_efi_arch():
    arch = ukify.guess_efi_arch()
    assert arch in ukify.EFI_ARCHES


def test_shell_join():
    assert ukify.shell_join(['a', 'b', ' ']) == "a b ' '"


def test_round_up():
    assert ukify.round_up(0) == 0
    assert ukify.round_up(4095) == 4096
    assert ukify.round_up(4096) == 4096
    assert ukify.round_up(4097) == 8192


def test_namespace_creation():
    ns = ukify.create_parser().parse_args(())
    assert ns.linux is None
    assert ns.initrd is None


def test_config_example():
    ex = ukify.config_example()
    assert '[UKI]' in ex
    assert 'Splash = BMP' in ex


def test_apply_config(tmp_path):
    config = tmp_path / 'config1.conf'
    config.write_text(
        textwrap.dedent(
            f'''
        [UKI]
        Linux = LINUX
        Initrd = initrd1 initrd2
                 initrd3
        Cmdline = 1 2 3 4 5
                  6 7 8
        OSRelease = @some/path1
        DeviceTree = some/path2
        Splash = some/path3
        Uname = 1.2.3
        EFIArch=arm
        Stub = some/path4
        PCRBanks = sha512,sha1
        SigningEngine = engine1
        SecureBootPrivateKey = some/path5
        SecureBootCertificate = some/path6
        SignKernel = no

        [PCRSignature:NAME]
        PCRPrivateKey = some/path7
        PCRPublicKey = some/path8
        Phases = {':'.join(ukify.KNOWN_PHASES)}
        '''
        )
    )

    ns = ukify.create_parser().parse_args(['build'])
    ns.linux = None
    ns.initrd = []
    ukify.apply_config(ns, config)

    assert ns.linux == pathlib.Path('LINUX')
    assert ns.initrd == [
        pathlib.Path('initrd1'),
        pathlib.Path('initrd2'),
        pathlib.Path('initrd3'),
    ]
    assert ns.cmdline == '1 2 3 4 5\n6 7 8'
    assert ns.os_release == '@some/path1'
    assert ns.devicetree == pathlib.Path('some/path2')
    assert ns.splash == pathlib.Path('some/path3')
    assert ns.efi_arch == 'arm'
    assert ns.stub == pathlib.Path('some/path4')
    assert ns.pcr_banks == ['sha512', 'sha1']
    assert ns.signing_engine == 'engine1'
    assert ns.sb_key == 'some/path5'
    assert ns.sb_cert == 'some/path6'
    assert ns.sign_kernel is False

    assert ns._groups == ['NAME']
    assert ns.pcr_private_keys == ['some/path7']
    assert ns.pcr_public_keys == ['some/path8']
    assert ns.phase_path_groups == [['enter-initrd:leave-initrd:sysinit:ready:shutdown:final']]

    ukify.finalize_options(ns)

    assert ns.linux == pathlib.Path('LINUX')
    assert ns.initrd == [
        pathlib.Path('initrd1'),
        pathlib.Path('initrd2'),
        pathlib.Path('initrd3'),
    ]
    assert ns.cmdline == '1 2 3 4 5 6 7 8'
    assert ns.os_release == pathlib.Path('some/path1')
    assert ns.devicetree == pathlib.Path('some/path2')
    assert ns.splash == pathlib.Path('some/path3')
    assert ns.efi_arch == 'arm'
    assert ns.stub == pathlib.Path('some/path4')
    assert ns.pcr_banks == ['sha512', 'sha1']
    assert ns.signing_engine == 'engine1'
    assert ns.sb_key == 'some/path5'
    assert ns.sb_cert == pathlib.Path('some/path6')
    assert ns.sign_kernel is False

    assert ns._groups == ['NAME']
    assert ns.pcr_private_keys == ['some/path7']
    assert ns.pcr_public_keys == ['some/path8']
    assert ns.phase_path_groups == [['enter-initrd:leave-initrd:sysinit:ready:shutdown:final']]


def test_parse_args_minimal():
    with pytest.raises(ValueError):
        ukify.parse_args([])

    opts = ukify.parse_args('arg1 arg2'.split())
    assert opts.linux == pathlib.Path('arg1')
    assert opts.initrd == [pathlib.Path('arg2')]
    assert opts.os_release in (
        pathlib.Path('/etc/os-release'),
        pathlib.Path('/usr/lib/os-release'),
    )


def test_parse_args_many_deprecated():
    opts = ukify.parse_args(
        [
            '/ARG1',
            '///ARG2',
            '/ARG3 WITH SPACE',
            '--cmdline=a b c',
            '--os-release=K1=V1\nK2=V2',
            '--devicetree=DDDDTTTT',
            '--splash=splash',
            '--pcrpkey=PATH',
            '--uname=1.2.3',
            '--stub=STUBPATH',
            '--pcr-private-key=PKEY1',
            '--pcr-public-key=PKEY2',
            '--pcr-banks=SHA1,SHA256',
            '--signing-engine=ENGINE',
            '--secureboot-private-key=SBKEY',
            '--secureboot-certificate=SBCERT',
            '--sign-kernel',
            '--no-sign-kernel',
            '--tools=TOOLZ///',
            '--output=OUTPUT',
            '--measure',
            '--no-measure',
        ]
    )
    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2'), pathlib.Path('/ARG3 WITH SPACE')]
    assert opts.cmdline == 'a b c'
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == ['PKEY1']
    assert opts.pcr_public_keys == ['PKEY2']
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.sb_key == 'SBKEY'
    assert opts.sb_cert == pathlib.Path('SBCERT')
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is False


def test_parse_args_many():
    opts = ukify.parse_args(
        [
            'build',
            '--linux=/ARG1',
            '--initrd=///ARG2',
            '--initrd=/ARG3 WITH SPACE',
            '--cmdline=a b c',
            '--os-release=K1=V1\nK2=V2',
            '--devicetree=DDDDTTTT',
            '--splash=splash',
            '--pcrpkey=PATH',
            '--uname=1.2.3',
            '--stub=STUBPATH',
            '--pcr-private-key=PKEY1',
            '--pcr-public-key=PKEY2',
            '--pcr-banks=SHA1,SHA256',
            '--signing-engine=ENGINE',
            '--secureboot-private-key=SBKEY',
            '--secureboot-certificate=SBCERT',
            '--sign-kernel',
            '--no-sign-kernel',
            '--tools=TOOLZ///',
            '--output=OUTPUT',
            '--measure',
            '--no-measure',
            '--policy-digest',
            '--no-policy-digest',
            '--sign-initrd-pcrs',
            '--no-sign-initrd-pcrs',
        ]
    )
    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2'), pathlib.Path('/ARG3 WITH SPACE')]
    assert opts.cmdline == 'a b c'
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == ['PKEY1']
    assert opts.pcr_public_keys == ['PKEY2']
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.sb_key == 'SBKEY'
    assert opts.sb_cert == pathlib.Path('SBCERT')
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is False
    assert opts.policy_digest is False
    assert opts.sign_initrd_pcrs is False


def test_parse_sections():
    opts = ukify.parse_args(
        [
            'build',
            '--linux=/ARG1',
            '--initrd=/ARG2',
            '--section=test:TESTTESTTEST',
            '--section=test2:@FILE',
        ]
    )

    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2')]
    assert len(opts.sections) == 2

    assert opts.sections[0].name == 'test'
    assert isinstance(opts.sections[0].content, pathlib.Path)
    assert opts.sections[0].tmpfile
    assert opts.sections[0].measure is False

    assert opts.sections[1].name == 'test2'
    assert opts.sections[1].content == pathlib.Path('FILE')
    assert opts.sections[1].tmpfile is None
    assert opts.sections[1].measure is False


def test_config_priority(tmp_path):
    config = tmp_path / 'config1.conf'
    # config: use pesign and give certdir + certname
    config.write_text(
        textwrap.dedent(
            f'''
        [UKI]
        Linux = LINUX
        Initrd = initrd1 initrd2
                 initrd3
        Cmdline = 1 2 3 4 5
                  6 7 8
        OSRelease = @some/path1
        DeviceTree = some/path2
        Splash = some/path3
        Uname = 1.2.3
        EFIArch = arm
        Stub = some/path4
        PCRBanks = sha512,sha1
        SigningEngine = engine1
        SecureBootSigningTool = pesign
        SecureBootCertificateDir = some/path5
        SecureBootCertificateName = some/name1
        SignKernel = no

        [PCRSignature:NAME]
        PCRPrivateKey = some/path7
        PCRPublicKey = some/path8
        Phases = {':'.join(ukify.KNOWN_PHASES)}
        '''
        )
    )

    # args: use sbsign and give key + cert, should override pesign
    opts = ukify.parse_args(
        [
            'build',
            '--linux=/ARG1',
            '--initrd=///ARG2',
            '--initrd=/ARG3 WITH SPACE',
            '--cmdline= a  b  c ',
            '--os-release=K1=V1\nK2=V2',
            '--devicetree=DDDDTTTT',
            '--splash=splash',
            '--pcrpkey=PATH',
            '--uname=1.2.3',
            '--stub=STUBPATH',
            '--pcr-private-key=PKEY1',
            '--pcr-public-key=PKEY2',
            '--pcr-banks=SHA1,SHA256',
            '--signing-engine=ENGINE',
            '--signtool=sbsign',
            '--secureboot-private-key=SBKEY',
            '--secureboot-certificate=SBCERT',
            '--sign-kernel',
            '--no-sign-kernel',
            '--tools=TOOLZ///',
            '--output=OUTPUT',
            '--measure',
        ]
    )

    ukify.apply_config(opts, config)
    ukify.finalize_options(opts)

    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [
        pathlib.Path('initrd1'),
        pathlib.Path('initrd2'),
        pathlib.Path('initrd3'),
        pathlib.Path('/ARG2'),
        pathlib.Path('/ARG3 WITH SPACE'),
    ]
    assert opts.cmdline == 'a b c'
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == ['PKEY1', 'some/path7']
    assert opts.pcr_public_keys == ['PKEY2', 'some/path8']
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.signtool == 'sbsign'  # from args
    assert opts.sb_key == 'SBKEY'  # from args
    assert opts.sb_cert == pathlib.Path('SBCERT')  # from args
    assert opts.sb_certdir == 'some/path5'  # from config
    assert opts.sb_cert_name == 'some/name1'  # from config
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is True


def test_help(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['--help'])
    out = capsys.readouterr()
    assert '--section' in out.out
    assert not out.err


def test_help_display(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['inspect', '--help'])
    out = capsys.readouterr()
    assert '--section' in out.out
    assert not out.err


def test_help_error_deprecated(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['a', 'b', '--no-such-option'])
    out = capsys.readouterr()
    assert not out.out
    assert '--no-such-option' in out.err
    assert len(out.err.splitlines()) == 1


def test_help_error(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['build', '--no-such-option'])
    out = capsys.readouterr()
    assert not out.out
    assert '--no-such-option' in out.err
    assert len(out.err.splitlines()) == 1


@pytest.fixture(scope='session')
def kernel_initrd():
    items = sorted(glob.glob('/lib/modules/*/vmlinuz'))
    if not items:
        items = sorted(glob.glob('/boot/vmlinuz*'))
    # Drop entries we cannot read (e.g. /boot/vmlinuz.old with mode 0600 on
    # GitHub-hosted runners), the test opens the file later and would fail.
    items = [p for p in items if os.access(p, os.R_OK)]
    if not items:
        return None

    # This doesn't necessarily give us the latest version, since we're just
    # using alphanumeric ordering. But this is fine, a predictable result is
    # enough.
    linux = items[-1]

    # We don't look _into_ the initrd. Any file is OK.
    return ['--linux', linux, '--initrd', ukify.__file__]


def test_check_splash():
    try:
        # pyflakes: noqa
        import PIL  # noqa
    except ImportError:
        pytest.skip('PIL not available')

    with pytest.raises(OSError):
        ukify.check_splash(os.devnull)


def test_basic_operation(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    output = f'{tmp_path}/basic.efi'
    opts = ukify.parse_args(
        [
            'build',
            *kernel_initrd,
            f'--output={output}',
        ]
    )
    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    subprocess.check_output(['objdump', '-h', output])

    shutil.rmtree(tmp_path)


def test_sections(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    output = f'{tmp_path}/basic.efi'
    opts = ukify.parse_args(
        [
            'build',
            *kernel_initrd,
            f'--output={output}',
            '--uname=1.2.3',
            '--cmdline=ARG1 ARG2 ARG3',
            '--os-release=K1=V1\nK2=V2\n',
            '--section=.test:CONTENTZ',
        ]
    )

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname test'.split():
        assert re.search(rf'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    shutil.rmtree(tmp_path)


@pytest.mark.parametrize(
    'name, string_table, match',
    [
        (b'/4', None, 'no COFF string table'),
        (b'/abc', b'\0' * 8, 'not a valid string table offset'),
        (b'/100', (8).to_bytes(4, 'little') + b'.foo\0', 'out of bounds'),
        (b'/4', (8).to_bytes(4, 'little') + b'.foo', 'not NUL-terminated'),
    ],
)
def test_pe_resolve_section_name_invalid_input(name, string_table, match):
    with pytest.raises(ukify.PEError, match=match):
        ukify.pe_resolve_section_name(name, string_table)


@pytest.fixture
def minimal_pe():
    """Create the smallest PE image that pe_add_sections() can still process"""
    FILE_ALIGNMENT = 512
    SECTION_ALIGNMENT = 4096
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    E_LFANEW_OFFSET = 0x3C  # fixed DOS header field pointing at the PE header
    PE_OFFSET = 0x40  # PE header right after the DOS header
    PE_MAGIC = b'PE\0\0'
    N_DATA_DIRECTORIES = 16
    data_directory_format = '<II'

    section_data = b'\0' * 16
    section_format = '<8sIIIIIIHHI'
    opt_format = '<HBBIIIIIQIIHHHHHHIIIIHHQQQQII'
    opt_header_size = struct.calcsize(opt_format) + N_DATA_DIRECTORIES * struct.calcsize(
        data_directory_format
    )

    coff = struct.pack(
        '<HHIIIHH',
        0x8664,  # Machine: EM_X86_64
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        opt_header_size,  # SizeOfOptionalHeader
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE,
    )

    # Reserve header room for one more section, so tests can append one
    header_size = (
        PE_OFFSET + len(PE_MAGIC) + len(coff) + opt_header_size + struct.calcsize(section_format) * 2
    )
    size_of_headers = ukify.round_up(header_size, FILE_ALIGNMENT)
    size_of_image = ukify.round_up(SECTION_ALIGNMENT + len(section_data), SECTION_ALIGNMENT)

    opt = struct.pack(
        opt_format,
        0x20B,  # Magic: PE32+
        0,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        0,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        SECTION_ALIGNMENT,  # AddressOfEntryPoint
        SECTION_ALIGNMENT,  # BaseOfCode
        0,  # ImageBase
        SECTION_ALIGNMENT,  # SectionAlignment
        FILE_ALIGNMENT,  # FileAlignment
        0,  # MajorOperatingSystemVersion
        0,  # MinorOperatingSystemVersion
        0,  # MajorImageVersion
        0,  # MinorImageVersion
        0,  # MajorSubsystemVersion
        0,  # MinorSubsystemVersion
        0,  # Win32VersionValue
        size_of_image,  # SizeOfImage
        size_of_headers,  # SizeOfHeaders
        0,  # CheckSum
        10,  # Subsystem: EFI application
        0,  # DllCharacteristics
        0,  # SizeOfStackReserve
        0,  # SizeOfStackCommit
        0,  # SizeOfHeapReserve
        0,  # SizeOfHeapCommit
        0,  # LoaderFlags
        N_DATA_DIRECTORIES,  # NumberOfRvaAndSizes
    ) + bytes(N_DATA_DIRECTORIES * struct.calcsize(data_directory_format))
    assert len(opt) == opt_header_size

    section = struct.pack(
        section_format,
        b'.text',
        len(section_data),  # VirtualSize
        SECTION_ALIGNMENT,  # VirtualAddress
        ukify.round_up(len(section_data), FILE_ALIGNMENT),  # SizeOfRawData
        size_of_headers,  # PointerToRawData
        0,  # PointerToRelocations
        0,  # PointerToLinenumbers
        0,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        0x60000020,  # Characteristics: CNT_CODE|MEM_EXECUTE|MEM_READ
    )

    buf = bytearray(b'MZ')
    buf += bytes(E_LFANEW_OFFSET - len(buf)) + struct.pack('<H', PE_OFFSET)
    buf += bytes(PE_OFFSET - len(buf)) + PE_MAGIC + coff + opt + section
    buf += bytes(size_of_headers - len(buf))
    buf += section_data + bytes(ukify.round_up(len(section_data), FILE_ALIGNMENT) - len(section_data))

    return pefile.PE(data=bytearray(buf), fast_load=True)


@pytest.fixture
def symbol_table_with_longnames():
    name = b'.longname'
    size = 4 + len(name) + 1
    return size.to_bytes(4, 'little') + name + b'\0'


@pytest.fixture
def symbol_table_empty():
    return (4).to_bytes(4, 'little')


def _attach_symbol_table(pe, table):
    table_start = ukify.round_up(len(pe.__data__), pe.OPTIONAL_HEADER.FileAlignment)
    pe.__data__ += bytes(table_start - len(pe.__data__)) + table
    pe.FILE_HEADER.PointerToSymbolTable = table_start
    pe.FILE_HEADER.NumberOfSymbols = 0


def _pe_to_file(pe, tmp_path):
    path = tmp_path / 'in.efi'
    pe.write(str(path))
    return path


def test_symbol_table_from_pe_invalid_string_table_size(minimal_pe):
    _attach_symbol_table(minimal_pe, (2).to_bytes(4, 'little'))
    with pytest.raises(ukify.PEError, match='invalid size'):
        ukify.SymbolTable.from_pe(minimal_pe)


@pytest.fixture
def pe_with_symbol_table(minimal_pe, symbol_table_with_longnames):
    pe = minimal_pe
    _attach_symbol_table(pe, symbol_table_with_longnames)
    pe.sections[-1].Name = b'/4'.ljust(8, b'\0')
    return pe


@pytest.fixture
def pe_with_symbol_table_file(pe_with_symbol_table, tmp_path):
    return _pe_to_file(pe_with_symbol_table, tmp_path)


@pytest.fixture
def pe_with_empty_symbol_table_file(minimal_pe, symbol_table_empty, tmp_path):
    _attach_symbol_table(minimal_pe, symbol_table_empty)
    return _pe_to_file(minimal_pe, tmp_path)


@pytest.fixture
def pe_with_misplaced_symbol_table_file(pe_with_symbol_table, tmp_path):
    """Simulate an older ukify that didn't relocate the table before appending sections."""
    pe = pe_with_symbol_table
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    new_section.__unpack__(b'\0' * new_section.sizeof())
    new_section.set_file_offset(pe.sections[-1].get_file_offset() + new_section.sizeof())
    new_section.Name = b'.stray'
    data = b'stray'
    new_section.Misc_VirtualSize = len(data)
    new_section.PointerToRawData = ukify.round_up(len(pe.__data__), pe.OPTIONAL_HEADER.FileAlignment)
    new_section.SizeOfRawData = ukify.round_up(len(data), pe.OPTIONAL_HEADER.FileAlignment)
    new_section.VirtualAddress = ukify.round_up(
        pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment,
    )
    new_section.IMAGE_SCN_MEM_READ = True
    new_section.IMAGE_SCN_CNT_INITIALIZED_DATA = True
    pe.__data__ += (
        bytes(new_section.PointerToRawData - len(pe.__data__))
        + data
        + bytes(new_section.SizeOfRawData - len(data))
    )
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfInitializedData += new_section.Misc_VirtualSize
    pe.__structures__.append(new_section)
    pe.sections.append(new_section)
    return _pe_to_file(pe, tmp_path)


@pytest.fixture
def pe_with_misplaced_symbol_table_and_cert_table_file(pe_with_misplaced_symbol_table_file, tmp_path):
    pe = pefile.PE(str(pe_with_misplaced_symbol_table_file), fast_load=True)
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
    security.VirtualAddress = ukify.round_up(len(pe.__data__), pe.OPTIONAL_HEADER.FileAlignment)
    security.Size = 8
    return _pe_to_file(pe, tmp_path)


@pytest.fixture
def pe_with_section_in_alignment_gap_file(pe_with_symbol_table, tmp_path):
    pe = pe_with_symbol_table
    table_end = len(pe.__data__)
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    new_section.__unpack__(b'\0' * new_section.sizeof())
    new_section.set_file_offset(pe.sections[-1].get_file_offset() + new_section.sizeof())
    new_section.Name = b'.stray'
    data = b'stray'
    new_section.Misc_VirtualSize = len(data)
    new_section.PointerToRawData = table_end
    new_section.SizeOfRawData = ukify.round_up(len(data), pe.OPTIONAL_HEADER.FileAlignment)
    new_section.VirtualAddress = ukify.round_up(
        pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment,
    )
    new_section.IMAGE_SCN_MEM_READ = True
    new_section.IMAGE_SCN_CNT_INITIALIZED_DATA = True
    pe.__data__ += data + bytes(new_section.SizeOfRawData - len(data))
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfInitializedData += new_section.Misc_VirtualSize
    pe.__structures__.append(new_section)
    pe.sections.append(new_section)
    return _pe_to_file(pe, tmp_path)


@pytest.fixture
def pe_section_overlaps_symbol_table_invalid_file(pe_with_symbol_table, tmp_path):
    pe = pe_with_symbol_table
    symbol_table_start = pe.FILE_HEADER.PointerToSymbolTable
    new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    new_section.__unpack__(b'\0' * new_section.sizeof())
    new_section.set_file_offset(pe.sections[-1].get_file_offset() + new_section.sizeof())
    new_section.Name = b'.stray'
    new_section.Misc_VirtualSize = 4
    new_section.PointerToRawData = symbol_table_start + 5
    new_section.SizeOfRawData = 4
    new_section.VirtualAddress = ukify.round_up(
        pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
        pe.OPTIONAL_HEADER.SectionAlignment,
    )
    new_section.IMAGE_SCN_MEM_READ = True
    new_section.IMAGE_SCN_CNT_INITIALIZED_DATA = True
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfInitializedData += new_section.Misc_VirtualSize
    pe.__structures__.append(new_section)
    pe.sections.append(new_section)
    return _pe_to_file(pe, tmp_path)


def assert_no_gaps(ukified_pe):
    prev_end = ukified_pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in ukified_pe.sections:
        assert section.PointerToRawData == prev_end, f'gap before {section.Name}'
        prev_end = section.PointerToRawData + section.SizeOfRawData


def assert_uki_after_symbol_table_sanitize(ukified_pe):
    # Referenced table is not stripped
    assert ukified_pe.FILE_HEADER.PointerToSymbolTable != 0
    assert not ukified_pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED

    assert_no_gaps(ukified_pe)

    # Every long-named section still resolves to its original name
    symbol_table = ukify.SymbolTable.from_pe(ukified_pe)
    string_table = symbol_table.string_table if symbol_table else None
    for section in ukified_pe.sections:
        if section.Name.startswith(b'/'):
            assert ukify.pe_resolve_section_name(section.Name, string_table) == '.longname'

    # Symbol table ends up in Authenticode's trailing-data range
    authenticode_extra_data_offset = ukified_pe.OPTIONAL_HEADER.SizeOfHeaders + sum(
        s.SizeOfRawData for s in ukified_pe.sections
    )
    assert ukified_pe.FILE_HEADER.PointerToSymbolTable >= authenticode_extra_data_offset


def test_pe_add_sections_strips_unreferenced_symbol_table(pe_with_empty_symbol_table_file, tmp_path):
    dst = tmp_path / 'out.efi'
    ukify.pe_add_sections(
        SimpleNamespace(pcrsig=None), ukify.UKI(executable=pe_with_empty_symbol_table_file), dst
    )
    ukified_pe = pefile.PE(str(dst), fast_load=True)

    assert ukified_pe.FILE_HEADER.PointerToSymbolTable == 0
    assert ukified_pe.FILE_HEADER.IMAGE_FILE_LOCAL_SYMS_STRIPPED
    assert_no_gaps(ukified_pe)


def test_pe_add_sections_keeps_referenced_symbol_table(pe_with_symbol_table_file, tmp_path):
    dst = tmp_path / 'out.efi'
    uki = ukify.UKI(executable=pe_with_symbol_table_file)
    uki.add_section(ukify.Section.create('.extra', b'extra section data'))
    ukify.pe_add_sections(SimpleNamespace(pcrsig=None), uki, dst)
    ukified_pe = pefile.PE(str(dst), fast_load=True)

    assert_uki_after_symbol_table_sanitize(ukified_pe)


def test_pe_add_sections_relocates_misplaced_symbol_table(pe_with_misplaced_symbol_table_file, tmp_path):
    dst = tmp_path / 'out.efi'
    ukify.pe_add_sections(
        SimpleNamespace(pcrsig=None), ukify.UKI(executable=pe_with_misplaced_symbol_table_file), dst
    )
    ukified_pe = pefile.PE(str(dst), fast_load=True)

    assert_uki_after_symbol_table_sanitize(ukified_pe)


def test_pe_add_sections_shifts_section_in_alignment_gap(pe_with_section_in_alignment_gap_file, tmp_path):
    dst = tmp_path / 'out.efi'
    ukify.pe_add_sections(
        SimpleNamespace(pcrsig=None),
        ukify.UKI(executable=pe_with_section_in_alignment_gap_file),
        dst,
    )
    ukified_pe = pefile.PE(str(dst), fast_load=True)

    assert_uki_after_symbol_table_sanitize(ukified_pe)
    stray = next(s for s in ukified_pe.sections if s.Name.rstrip(b'\0') == b'.stray')
    assert ukified_pe.__data__[stray.PointerToRawData : stray.PointerToRawData + 5] == b'stray'


def test_pe_add_sections_section_overlapping_symbol_table(
    pe_section_overlaps_symbol_table_invalid_file, tmp_path
):
    with pytest.raises(ukify.PEError, match='section pointer into symbol table'):
        ukify.pe_add_sections(
            SimpleNamespace(pcrsig=None),
            ukify.UKI(executable=pe_section_overlaps_symbol_table_invalid_file),
            tmp_path / 'out.efi',
        )


def test_pe_add_sections_with_cert_table_without_pcrsig(
    pe_with_misplaced_symbol_table_and_cert_table_file, tmp_path
):
    with pytest.raises(ukify.PEError):
        ukify.pe_add_sections(
            SimpleNamespace(pcrsig=None),
            ukify.UKI(executable=pe_with_misplaced_symbol_table_and_cert_table_file),
            tmp_path / 'out.efi',
        )


def test_pe_add_sections_with_cert_table_and_pcrsig_leaves_symbol_table_untouched(
    pe_with_misplaced_symbol_table_and_cert_table_file, tmp_path
):
    original_pe = pefile.PE(str(pe_with_misplaced_symbol_table_and_cert_table_file), fast_load=True)

    dst = tmp_path / 'out.efi'
    ukify.pe_add_sections(
        SimpleNamespace(pcrsig='{}'),
        ukify.UKI(executable=pe_with_misplaced_symbol_table_and_cert_table_file),
        dst,
    )
    ukified_pe = pefile.PE(str(dst), fast_load=True)

    assert ukified_pe.FILE_HEADER.PointerToSymbolTable == original_pe.FILE_HEADER.PointerToSymbolTable
    assert ukified_pe.FILE_HEADER.NumberOfSymbols == original_pe.FILE_HEADER.NumberOfSymbols
    assert ukify.SymbolTable.from_pe(ukified_pe).data == ukify.SymbolTable.from_pe(original_pe).data


def test_addon(tmp_path):
    output = f'{tmp_path}/addon.efi'
    args = [
        'build',
        f'--output={output}',
        '--cmdline=ARG1 ARG2 ARG3',
        '''--sbat=sbat,1,foo
foo,1
bar,2
''',
        '--section=.test:CONTENTZ',
        '''--sbat=sbat,1,foo
baz,3
''',
    ]
    if stub := os.getenv('EFI_ADDON'):
        args += [f'--stub={stub}']
        expected_exceptions = ()
    else:
        expected_exceptions = (FileNotFoundError,)

    opts = ukify.parse_args(args)
    try:
        ukify.check_inputs(opts)
    except expected_exceptions as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text cmdline test sbat'.split():
        assert re.search(rf'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    pe = pefile.PE(output, fast_load=True)
    found = False

    for section in pe.sections:
        if section.Name.rstrip(b'\x00').decode() == '.sbat':
            assert found is False
            split = section.get_data().rstrip(b'\x00').decode().splitlines()
            assert split == [
                'sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md',
                'foo,1',
                'bar,2',
                'baz,3',
            ]
            found = True

    assert found is True


def unbase64(filename):
    tmp = tempfile.NamedTemporaryFile()
    base64.decode(filename.open('rb'), tmp)
    tmp.flush()
    return tmp


def test_uname_scraping(kernel_initrd):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    assert kernel_initrd[0] == '--linux'
    uname = ukify.Uname.scrape(kernel_initrd[1])
    assert re.match(r'\d+\.\d+\.\d+', uname)


@pytest.mark.skipif(not slow_tests, reason='slow')
@pytest.mark.parametrize('days', [365 * 10, None])
def test_efi_signing_sbsign(days, kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('sbsign'):
        pytest.skip('sbsign not found')

    ourdir = pathlib.Path(__file__).parent
    cert = unbase64(ourdir / 'example.signing.crt.base64')
    key = unbase64(ourdir / 'example.signing.key.base64')

    output = f'{tmp_path}/signed.efi'
    args = [
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        f'--secureboot-certificate={cert.name}',
        f'--secureboot-private-key={key.name}',
    ]
    if days is not None:
        args += [f'--secureboot-certificate-validity={days}']

    opts = ukify.parse_args(args)

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    if shutil.which('sbverify'):
        # let's check that sbverify likes the resulting file
        dump = subprocess.check_output(
            [
                'sbverify',
                '--cert', cert.name,
                output,
            ],
            text=True,
        )  # fmt: skip

        assert 'Signature verification OK' in dump

    shutil.rmtree(tmp_path)


@pytest.mark.skipif(not slow_tests, reason='slow')
def test_efi_signing_pesign(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('pesign'):
        pytest.skip('pesign not found')

    nss_db = f'{tmp_path}/nss_db'
    name = 'Test_Secureboot'
    author = 'systemd'

    subprocess.check_call(['mkdir', '-p', nss_db])
    cmd = f'certutil -N --empty-password -d {nss_db}'.split(' ')
    subprocess.check_call(cmd)
    cmd = f'efikeygen -d {nss_db} -S -k -c CN={author} -n {name}'.split(' ')
    subprocess.check_call(cmd)

    output = f'{tmp_path}/signed.efi'
    opts = ukify.parse_args(
        [
            'build',
            *kernel_initrd,
            f'--output={output}',
            '--uname=1.2.3',
            '--signtool=pesign',
            '--cmdline=ARG1 ARG2 ARG3',
            f'--secureboot-certificate-name={name}',
            f'--secureboot-certificate-dir={nss_db}',
        ]
    )

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that pesign likes the resulting file
    dump = subprocess.check_output(
        [
            'pesign',
            '-S',
            '-i', output,
        ],
        text=True,
    )  # fmt: skip

    assert f"The signer's common name is {author}" in dump

    shutil.rmtree(tmp_path)


def test_inspect(kernel_initrd, tmp_path, capsys, osrel=True):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('sbsign'):
        pytest.skip('sbsign not found')

    ourdir = pathlib.Path(__file__).parent
    cert = unbase64(ourdir / 'example.signing.crt.base64')
    key = unbase64(ourdir / 'example.signing.key.base64')

    output = f'{tmp_path}/signed2.efi'
    uname_arg = '1.2.3'
    osrel_arg = 'Linux' if osrel else ''
    cmdline_arg = 'ARG1 ARG2 ARG3'

    args = [
        'build',
        *kernel_initrd,
        f'--cmdline={cmdline_arg}',
        f'--os-release={osrel_arg}',
        f'--uname={uname_arg}',
        f'--output={output}',
    ] + arg_tools
    if slow_tests:
        args += [
            f'--secureboot-certificate={cert.name}',
            f'--secureboot-private-key={key.name}',
        ]

    opts = ukify.parse_args(args)

    ukify.check_inputs(opts)
    ukify.make_uki(opts)

    opts = ukify.parse_args(['inspect', output])
    ukify.inspect_sections(opts)

    text = capsys.readouterr().out

    if osrel:
        expected_osrel = f'.osrel:\n  size: {len(osrel_arg)}'
        assert expected_osrel in text
    else:
        assert '.osrel:' not in text

    expected_cmdline = f'.cmdline:\n  size: {len(cmdline_arg)}'
    assert expected_cmdline in text
    expected_uname = f'.uname:\n  size: {len(uname_arg)}'
    assert expected_uname in text

    expected_initrd = '.initrd:\n  size:'
    assert expected_initrd in text
    expected_linux = '.linux:\n  size:'
    assert expected_linux in text

    shutil.rmtree(tmp_path)


def test_inspect_no_osrel(kernel_initrd, tmp_path, capsys):
    test_inspect(kernel_initrd, tmp_path, capsys, osrel=False)


def build_inspect_uki(*args):
    # Build a UKI for the inspect-JSON tests. Building needs a stub; CI provides the addon stub via
    # $EFI_ADDON (see test_addon), so build addon-style (no --linux) to need only that one. Skip if
    # the stub is unavailable.
    stub = os.getenv('EFI_ADDON')
    if not stub:
        pytest.skip('EFI_ADDON not set')
    opts = ukify.parse_args(['build', f'--stub={stub}', *args, *arg_tools])
    try:
        ukify.check_inputs(opts)
    except FileNotFoundError as e:
        pytest.skip(str(e))
    ukify.make_uki(opts)


def test_inspect_json_profiles(tmp_path, capsys):
    # Build two standalone profile PE binaries, each carrying its own '.cmdline'.
    profiles = []
    for i in range(2):
        profile = f'{tmp_path}/profile{i}.efi'
        build_inspect_uki(f'--profile=ID=profile{i}', f'--cmdline=PROFILE{i}ARG', f'--output={profile}')
        profiles.append(profile)

    # Build the base UKI joining both profiles. The result has a shared base '.cmdline' plus one
    # '.cmdline' (and one '.profile') per profile, including the implicit base profile.
    output = f'{tmp_path}/base.efi'
    build_inspect_uki(
        '--cmdline=BASEARG',
        '--uname=1.2.3',
        *(f'--join-profile={p}' for p in profiles),
        f'--output={output}',
    )

    opts = ukify.parse_args(['inspect', output, '--json=short'])
    ukify.inspect_sections(opts)
    result = json.loads(capsys.readouterr().out)

    # Shared base sections stay keyed by name at the top level, just as for a profile-less UKI, so
    # the base '.cmdline' is not overwritten by the profile-specific ones.
    assert result['.cmdline']['text'] == 'BASEARG'
    assert result['.uname']['text'] == '1.2.3'

    # Implicit base profile (ID=main) plus the two joined profiles, each keyed by section name and
    # starting with its '.profile' section.
    assert len(result['_profiles']) == 3
    assert [p['.profile']['text'] for p in result['_profiles']] == ['ID=main', 'ID=profile0', 'ID=profile1']

    # Each joined profile's distinct '.cmdline' survives instead of being overwritten.
    profile_cmdlines = [p['.cmdline']['text'] for p in result['_profiles'] if '.cmdline' in p]
    assert profile_cmdlines == ['PROFILE0ARG', 'PROFILE1ARG']

    shutil.rmtree(tmp_path)


def test_inspect_json_alternative_set_sections(tmp_path, capsys):
    # '.dtbauto' and '.efifw' are alternative-sets (one entry per hardware variant): every occurrence
    # must be preserved, and they are always reported as a list, even for a single entry. The two are
    # built differently ('.efifw' via --efifw on a directory, measure=False) but flow through the same
    # list path, so both are exercised.
    def inspect(output):
        opts = ukify.parse_args(['inspect', str(output), '--json=short'])
        ukify.inspect_sections(opts)
        return json.loads(capsys.readouterr().out)

    dtbs = []
    for i in range(2):
        dtb = tmp_path / f'dtb{i}'
        dtb.write_bytes(f'DTB{i}'.encode())
        dtbs.append(dtb)

    # --efifw takes a directory containing exactly one firmware file; the fwid is the directory name.
    efifws = []
    for i in range(2):
        fwdir = tmp_path / f'fw{i}'
        fwdir.mkdir()
        (fwdir / 'firmware.bin').write_bytes(f'EFIFW{i}'.encode())
        efifws.append(fwdir)

    output = f'{tmp_path}/alt.efi'
    build_inspect_uki(
        '--cmdline=ARG',
        *(f'--devicetree-auto={d}' for d in dtbs),
        *(f'--efifw={d}' for d in efifws),
        f'--output={output}',
    )
    result = inspect(output)

    # No profiles, so no '_profiles' key and single sections stay plain objects (backwards compatible).
    assert '_profiles' not in result
    assert result['.cmdline']['text'] == 'ARG'

    # Both occurrences of each alternative-set section are preserved as a list, none dropped.
    for name in ('.dtbauto', '.efifw'):
        assert isinstance(result[name], list), name
        assert len(result[name]) == 2, name
        assert all('sha256' in d for d in result[name]), name
        assert result[name][0]['sha256'] != result[name][1]['sha256'], name

    # A single entry is still reported as a (one-element) list, not a bare object.
    single = f'{tmp_path}/single.efi'
    build_inspect_uki(f'--devicetree-auto={dtbs[0]}', f'--efifw={efifws[0]}', f'--output={single}')
    result = inspect(single)
    assert isinstance(result['.dtbauto'], list) and len(result['.dtbauto']) == 1
    assert isinstance(result['.efifw'], list) and len(result['.efifw']) == 1

    shutil.rmtree(tmp_path)


@pytest.mark.skipif(not slow_tests, reason='slow')
def test_pcr_signing(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    try:
        systemd_measure()
    except ValueError:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')

    output = f'{tmp_path}/signed.efi'
    args = [
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=ID=foobar\n',
        '--pcr-banks=sha384',  # sha1 might not be allowed, use something else
        f'--pcr-private-key={priv.name}',
    ] + arg_tools

    # If the public key is not explicitly specified, it is derived
    # automatically. Let's make sure everything works as expected both when the
    # public keys is specified explicitly and when it is derived from the
    # private key.
    for extra in ([f'--pcrpkey={pub.name}', f'--pcr-public-key={pub.name}'], []):
        opts = ukify.parse_args(args + extra)
        try:
            ukify.check_inputs(opts)
        except OSError as e:
            pytest.skip(str(e))

        ukify.make_uki(opts)

        # let's check that objdump likes the resulting file
        dump = subprocess.check_output(['objdump', '-h', output], text=True)

        for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
            assert re.search(rf'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

        # objcopy fails when called without an output argument (EPERM).
        # It also fails when called with /dev/null (file truncated).
        # It also fails when called with /dev/zero (because it reads the
        # output file, infinitely in this case.)
        # So let's just call it with a dummy output argument.
        subprocess.check_call(
            [
                'objcopy',
                *(
                    f'--dump-section=.{n}={tmp_path}/out.{n}'
                    for n in ('pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline')
                ),
                output,
                tmp_path / 'dummy',
            ],
            text=True,
        )

        assert open(tmp_path / 'out.pcrpkey').read() == open(pub.name).read()
        assert open(tmp_path / 'out.osrel').read() == 'ID=foobar\n'
        assert open(tmp_path / 'out.uname').read() == '1.2.3'
        assert open(tmp_path / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
        sig = open(tmp_path / 'out.pcrsig').read()
        sig = json.loads(sig)
        assert list(sig.keys()) == ['sha384']
        assert len(sig['sha384']) == 4  # four items for four phases

    shutil.rmtree(tmp_path)


@pytest.mark.skipif(not slow_tests, reason='slow')
def test_pcr_signing2(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    try:
        systemd_measure()
    except ValueError:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')
    pub2 = unbase64(ourdir / 'example.tpm2-pcr-public2.pem.base64')
    priv2 = unbase64(ourdir / 'example.tpm2-pcr-private2.pem.base64')

    # simulate a microcode file
    with open(f'{tmp_path}/microcode', 'wb') as microcode:
        microcode.write(b'1234567890')

    output = f'{tmp_path}/signed.efi'
    assert kernel_initrd[0] == '--linux'
    opts = ukify.parse_args(
        [
            'build',
            *kernel_initrd[:2],
            f'--initrd={microcode.name}',
            *kernel_initrd[2:],
            f'--output={output}',
            '--uname=1.2.3',
            '--cmdline=ARG1 ARG2 ARG3',
            '--os-release=ID=foobar\n',
            '--pcr-banks=sha384',
            f'--pcrpkey={pub2.name}',
            f'--pcr-public-key={pub.name}',
            f'--pcr-private-key={priv.name}',
            '--phases=enter-initrd enter-initrd:leave-initrd',
            f'--pcr-public-key={pub2.name}',
            f'--pcr-private-key={priv2.name}',
            '--phases=sysinit ready shutdown final',  # yes, those phase paths are not reachable
        ]
        + arg_tools
    )

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
        assert re.search(rf'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    subprocess.check_call(
        [
            'objcopy',
            *(
                f'--dump-section=.{n}={tmp_path}/out.{n}'
                for n in ('pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline', 'initrd')
            ),
            output,
            tmp_path / 'dummy',
        ],
        text=True,
    )

    assert open(tmp_path / 'out.pcrpkey').read() == open(pub2.name).read()
    assert open(tmp_path / 'out.osrel').read() == 'ID=foobar\n'
    assert open(tmp_path / 'out.uname').read() == '1.2.3'
    assert open(tmp_path / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
    assert open(tmp_path / 'out.initrd', 'rb').read(10) == b'1234567890'

    sig = open(tmp_path / 'out.pcrsig').read()
    sig = json.loads(sig)
    assert list(sig.keys()) == ['sha384']
    assert len(sig['sha384']) == 6  # six items for six phases paths

    shutil.rmtree(tmp_path)


@pytest.mark.skipif(not slow_tests, reason='slow')
def test_pcr_signing3(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    try:
        systemd_measure()
    except ValueError:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')

    # simulate a microcode file
    with open(f'{tmp_path}/microcode', 'wb') as microcode:
        microcode.write(b'1234567890')

    output = f'{tmp_path}/signed.efi'
    assert kernel_initrd[0] == '--linux'
    opts = ukify.parse_args(
        [
            'build',
            *kernel_initrd[:2],
            f'--initrd={microcode.name}',
            *kernel_initrd[2:],
            f'--output={output}',
            '--uname=1.2.3',
            '--cmdline=ARG1 ARG2 ARG3',
            '--os-release=ID=foobar\n',
            '--pcr-banks=sha384',
            f'--pcrpkey={pub.name}',
            f'--pcr-private-key={priv.name}',
            '--phases=enter-initrd enter-initrd:leave-initrd enter-initrd:leave-initrd:sysinit enter-initrd:leave-initrd:sysinit:ready',
            '--policyref=',
            f'--pcr-private-key={priv.name}',
            '--phases=enter-initrd',
            '--policyref=initrd',
        ]
        + arg_tools
    )

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
        assert re.search(rf'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    subprocess.check_call(
        [
            'objcopy',
            *(
                f'--dump-section=.{n}={tmp_path}/out.{n}'
                for n in ('pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline', 'initrd')
            ),
            output,
            tmp_path / 'dummy',
        ],
        text=True,
    )

    assert open(tmp_path / 'out.pcrpkey').read() == open(pub.name).read()
    assert open(tmp_path / 'out.osrel').read() == 'ID=foobar\n'
    assert open(tmp_path / 'out.uname').read() == '1.2.3'
    assert open(tmp_path / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
    assert open(tmp_path / 'out.initrd', 'rb').read(10) == b'1234567890'

    sig = open(tmp_path / 'out.pcrsig').read()
    sig = json.loads(sig)
    assert list(sig.keys()) == ['sha384']
    assert len(sig['sha384']) == 5  # five items for five phases paths
    assert 'ref' not in sig['sha384'][0]
    assert 'ref' not in sig['sha384'][1]
    assert 'ref' not in sig['sha384'][2]
    assert 'ref' not in sig['sha384'][3]
    assert 'ref' in sig['sha384'][4]
    assert sig['sha384'][4]['ref'] == 'initrd'

    shutil.rmtree(tmp_path)


def test_pcr_signing_initrd_pcrs(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    try:
        systemd_measure()
    except ValueError:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')

    output = f'{tmp_path}/signed.efi'
    args = [
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=ID=foobar\n',
        '--pcr-banks=sha384',  # sha1 might not be allowed, use something else
        f'--pcr-private-key={priv.name}',
        f'--pcr-public-key={pub.name}',
        '--sign-initrd-pcrs',
    ] + arg_tools

    opts = ukify.parse_args(args)
    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    subprocess.check_call(
        ['objcopy', f'--dump-section=.pcrsig={tmp_path}/out.pcrsig', output, tmp_path / 'dummy'],
        text=True,
    )

    sig = json.loads(open(tmp_path / 'out.pcrsig').read())
    assert list(sig.keys()) == ['sha384']
    assert len(sig['sha384']) == 5  # five items for five phase paths
    assert 'ref' not in sig['sha384'][0]
    assert 'ref' not in sig['sha384'][1]
    assert 'ref' not in sig['sha384'][2]
    assert 'ref' not in sig['sha384'][3]
    assert 'ref' in sig['sha384'][4]
    assert sig['sha384'][4]['ref'] == 'initrd'

    shutil.rmtree(tmp_path)


def test_key_cert_generation(tmp_path):
    opts = ukify.parse_args(
        [
            'genkey',
            f'--pcr-public-key={tmp_path / "pcr1.pub.pem"}',
            f'--pcr-private-key={tmp_path / "pcr1.priv.pem"}',
            '--phases=enter-initrd enter-initrd:leave-initrd',
            f'--pcr-public-key={tmp_path / "pcr2.pub.pem"}',
            f'--pcr-private-key={tmp_path / "pcr2.priv.pem"}',
            '--phases=sysinit ready',
            f'--secureboot-private-key={tmp_path / "sb.priv.pem"}',
            f'--secureboot-certificate={tmp_path / "sb.cert.pem"}',
        ]
    )
    assert opts.verb == 'genkey'
    ukify.check_cert_and_keys_nonexistent(opts)

    pytest.importorskip('cryptography')

    ukify.generate_keys(opts)

    if not shutil.which('openssl'):
        return

    for key in (tmp_path / 'pcr1.priv.pem', tmp_path / 'pcr2.priv.pem', tmp_path / 'sb.priv.pem'):
        out = subprocess.check_output(
            [
                'openssl', 'rsa',
                '-in', key,
                '-text',
                '-noout',
            ],
            text=True,
        )  # fmt: skip
        assert 'Private-Key' in out
        assert '2048 bit' in out

    for pub in (tmp_path / 'pcr1.pub.pem', tmp_path / 'pcr2.pub.pem'):
        out = subprocess.check_output(
            [
                'openssl', 'rsa',
                '-pubin',
                '-in', pub,
                '-text',
                '-noout',
            ],
            text=True,
        )  # fmt: skip
        assert 'Public-Key' in out
        assert '2048 bit' in out

    out = subprocess.check_output(
        [
            'openssl', 'x509',
            '-in', tmp_path / 'sb.cert.pem',
            '-text',
            '-noout',
        ],
        text=True,
    )  # fmt: skip
    assert 'Certificate' in out
    assert re.search(r'Issuer: CN\s?=\s?SecureBoot signing key on host', out)


def test_key_cert_generation_common_name(tmp_path):
    opts = ukify.parse_args(
        [
            'genkey',
            f'--secureboot-private-key={tmp_path / "sb.priv.pem"}',
            f'--secureboot-certificate={tmp_path / "sb.cert.pem"}',
            '--secureboot-certificate-common-name=ukify test key',
        ]
    )
    assert opts.verb == 'genkey'

    pytest.importorskip('cryptography')

    ukify.generate_keys(opts)

    if not shutil.which('openssl'):
        return

    out = subprocess.check_output(
        [
            'openssl', 'x509',
            '-in', tmp_path / 'sb.cert.pem',
            '-text',
            '-noout',
        ],
        text=True,
    )  # fmt: skip
    assert re.search(r'Subject: CN\s?=\s?ukify test key', out)
    assert re.search(r'Issuer: CN\s?=\s?ukify test key', out)


def test_key_cert_generation_empty_common_name(tmp_path):
    opts = ukify.parse_args(
        [
            'genkey',
            f'--secureboot-private-key={tmp_path / "sb.priv.pem"}',
            f'--secureboot-certificate={tmp_path / "sb.cert.pem"}',
            '--secureboot-certificate-common-name=',
        ]
    )

    with pytest.raises(ValueError, match='--secureboot-certificate-common-name= must not be empty'):
        ukify.generate_keys(opts)


def test_key_cert_generation_common_name_too_long(tmp_path):
    opts = ukify.parse_args(
        [
            'genkey',
            f'--secureboot-private-key={tmp_path / "sb.priv.pem"}',
            f'--secureboot-certificate={tmp_path / "sb.cert.pem"}',
            f'--secureboot-certificate-common-name={"x" * 65}',
        ]
    )

    with pytest.raises(ValueError, match='is longer than 64 bytes'):
        ukify.generate_keys(opts)


@pytest.mark.skipif(not slow_tests, reason='slow')
def test_join_pcrsig(capsys, kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    try:
        systemd_measure()
    except ValueError:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')

    output = tmp_path / 'basic.efi'
    args = [
        'build',
        *kernel_initrd,
        f'--output={output}',
        f'--pcr-public-key={pub.name}',
        '--json=short',
        '--policy-digest',
    ] + arg_tools
    opts = ukify.parse_args(args)
    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)
    pcrs = json.loads(capsys.readouterr().out)
    for bank, sigs in pcrs.items():
        for sig in sigs:
            sig['sig'] = 'a' * int(bank[3:])

    opts = ukify.parse_args(['inspect', str(output)])
    ukify.inspect_sections(opts)
    text = capsys.readouterr().out
    assert re.search(r'\.pcrpkey', text, re.MULTILINE)
    assert re.search(r'\.pcrsig', text, re.MULTILINE)
    assert not re.search(r'"sig":', text, re.MULTILINE)

    output_sig = tmp_path / 'pcrsig.efi'
    args = [
        'build',
        f'--output={output_sig}',
        f'--join-pcrsig={output}',
        f'--pcrsig={json.dumps(pcrs)}',
        '--json=short',
    ] + arg_tools
    opts = ukify.parse_args(args)
    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    opts = ukify.parse_args(['inspect', str(output_sig)])
    ukify.inspect_sections(opts)
    text = capsys.readouterr().out
    assert re.search(r'\.pcrpkey', text, re.MULTILINE)
    assert re.search(r'\.pcrsig', text, re.MULTILINE)
    assert re.search(r'"sig":', text, re.MULTILINE)

    shutil.rmtree(tmp_path)


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv))
