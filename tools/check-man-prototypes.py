#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import glob
import os
import re
import sys
from dataclasses import dataclass

try:
    import lxml.etree as tree
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

_parser = tree.XMLParser(resolve_entities=False)
tree.set_default_parser(_parser)


@dataclass
class Param:
    type: str
    name: str
    arraydims: str = ''
    varargs: bool = False


@dataclass
class Proto:
    name: str
    ret: str
    params: list
    is_typedef: bool = False


@dataclass
class MacroProto:
    """Represents a function-like macro with only argument names (no types)."""

    name: str
    param_names: list  # List of argument names (strings), '...' for varargs


@dataclass
class ManProto:
    name: str
    ret: str
    params: list
    is_typedef: bool
    filename: str


def normalize_type(s):
    """Normalize type string: collapse whitespace and normalize pointer spacing."""
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'\s*\*\s*', '*', s)
    # Normalize "unsigned" to "unsigned int"
    s = re.sub(r'\bunsigned\b(?!\s+(?:char|short|int|long))', 'unsigned int', s)
    return s


def normalize_arr(s):
    """Normalize array dimensions."""
    return re.sub(r'\s+', ' ', s).strip()


def remove_attributes(text):
    """Remove __attribute__((...)) with proper bracket matching."""
    result = []
    i = 0
    while i < len(text):
        # Look for __attribute__
        if text[i : i + 13] == '__attribute__':
            # Skip __attribute__
            i += 13
            # Skip whitespace
            while i < len(text) and text[i].isspace():
                i += 1
            # Skip balanced parentheses
            if i < len(text) and text[i] == '(':
                depth = 0
                while i < len(text):
                    if text[i] == '(':
                        depth += 1
                    elif text[i] == ')':
                        depth -= 1
                        if depth == 0:
                            i += 1
                            break
                    i += 1
        else:
            result += [text[i]]
            i += 1
    return ''.join(result)


def remove_braced_blocks(text):
    """Replace balanced {...} blocks with ';' to remove function bodies and struct definitions."""
    result = []
    i = 0
    while i < len(text):
        if text[i] == '{':
            # Found opening brace, skip to matching closing brace
            depth = 1
            i += 1
            while i < len(text) and depth > 0:
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                i += 1
            # Replace the entire block with ';'
            result += [';']
        else:
            result += [text[i]]
            i += 1
    return ''.join(result)


def extract_function_macros(text):
    """Extract function-like macros from preprocessor-intact text.
    Returns a dict of macro_name -> MacroProto."""
    macros = {}
    # Match #define NAME(args) where NAME is directly followed by '(' (no space)
    for match in re.finditer(r'^\s*#\s*define\s+(\w+)\(([^)]*)\)', text, re.MULTILINE):
        name = match.group(1)
        args_str = match.group(2).strip()

        if not args_str:
            param_names = []
        else:
            # Split by comma and strip
            param_names = [arg.strip() for arg in args_str.split(',')]

        macros[name] = MacroProto(name=name, param_names=param_names)

    return macros


def split_params(params_str):
    """Split parameter string into list of Param objects."""
    params_str = params_str.strip()
    if not params_str or params_str == 'void':
        return []

    # Split by top-level commas (not inside parentheses)
    parts = []
    depth = 0
    current = []
    for char in params_str:
        if char == ',' and depth == 0:
            parts += [''.join(current)]
            current = []
        else:
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            current += [char]
    if current:
        parts += [''.join(current)]

    params = []
    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Varargs
        if part == '...':
            params += [Param(type='', name='', varargs=True)]
            continue

        # Inline function pointer: type (*name)(...)
        if fp_match := re.search(r'\(\s*\*\s*(\w+)\s*\)', part):
            pname = fp_match.group(1)
            params += [Param(type=normalize_type(part), name=pname)]
            continue

        # Extract array dimensions from the end
        arraydims = ''
        if arr_match := re.search(r'(\[[^\]]*\])+\s*$', part):
            arraydims = normalize_arr(arr_match.group(0))
            part = part[: arr_match.start()]

        # Last word is name, rest is type
        tokens = re.findall(r'\w+|\*+', part)
        if not tokens:
            continue

        # If last token is *, it's part of type (no name)
        if tokens[-1].startswith('*'):
            ptype = normalize_type(part)
            pname = ''
        else:
            pname = tokens[-1]
            ptype = normalize_type(' '.join(tokens[:-1]))

        params += [Param(type=ptype, name=pname, arraydims=arraydims)]

    return params


def parse_headers(root):
    """Parse C headers and extract function prototypes and macros.
    Returns (functions, macros) where:
    - functions: dict of name -> Proto (with full type info)
    - macros: dict of name -> MacroProto (arg names only)
    """
    functions = {}
    macros = {}
    typedef_aliases = {}  # Maps new_name -> existing_name for simple typedefs

    header_files = glob.glob(os.path.join(root, 'src/systemd/*.h'))
    header_files += glob.glob(os.path.join(root, 'src/libudev/*.h'))

    for header in header_files:
        with open(header, encoding='utf-8') as f:
            text = f.read()

        # Remove C comments
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        text = re.sub(r'//.*?$', '', text, flags=re.MULTILINE)

        # Extract function-like macros BEFORE removing preprocessor directives
        header_macros = extract_function_macros(text)
        macros.update(header_macros)

        # Remove preprocessor directives (including multi-line with backslash continuation)
        text = re.sub(r'^\s*#.*?(?:\\\n.*?)*$', '', text, flags=re.MULTILINE)

        # Expand ref/unref macros
        text = re.sub(
            r'_SD_DECLARE_TRIVIAL_REF_UNREF_FUNC\(\s*(\w+)\s*\)',
            r'\1* \1_ref(\1 *p); \1* \1_unref(\1 *p)',
            text,
        )
        text = re.sub(
            r'_SD_DECLARE_TRIVIAL_REF_FUNC\(\s*(\w+)\s*\)',
            r'\1* \1_ref(\1 *p)',
            text,
        )
        text = re.sub(
            r'_SD_DECLARE_TRIVIAL_UNREF_FUNC\(\s*(\w+)\s*\)',
            r'\1* \1_unref(\1 *p)',
            text,
        )

        # Expand cleanup pointer macros
        text = re.sub(
            r'_SD_DEFINE_POINTER_CLEANUP_FUNC\(\s*(\w+)\s*,\s*(\w+)\s*\)',
            r'void \2p(\1 **p)',
            text,
        )

        # Replace _SD_ARRAY_STATIC with static
        text = text.replace('_SD_ARRAY_STATIC', 'static')

        # Remove __extension__
        text = text.replace('__extension__', '')

        # Remove extern "C" linkage (before braced block removal to avoid deleting everything)
        text = re.sub(r'extern\s+"C"\s*\{', '', text)
        text = re.sub(r'extern\s+"C"\s+', '', text)

        # Remove __attribute__((...))
        text = remove_attributes(text)

        # Remove _sd_..._ attribute macros (but not _sd_destroy_t typedef)
        # Pattern: _sd_<word>_ optionally followed by (...)
        text = re.sub(r'\b_sd_[A-Za-z0-9_]+_\b\s*(\([^;()]*\))?', '', text)

        # Remove balanced {...} blocks (function bodies, struct/union/enum definitions)
        # This also helps with inline functions
        text = remove_braced_blocks(text)

        # Split into statements by semicolon
        statements = text.split(';')

        for stmt in statements:
            stmt = re.sub(r'\s+', ' ', stmt).strip()
            if not stmt:
                continue

            # Skip statements with equals (initializers)
            if '=' in stmt:
                continue
            # Remove leading '}' (end of previous block)
            stmt = stmt.lstrip('}').strip()
            if not stmt:
                continue

            # Remove leading storage-class and inline specifiers (static, inline, __inline__, __inline, extern)
            # Only at the start of the statement to avoid breaking array modifiers like [static N]
            # Repeat until no more matches to handle combinations like "static __inline__"
            while re.match(r'^(?:static|inline|__inline__|__inline|extern)\s+', stmt):
                stmt = re.sub(r'^(?:static|inline|__inline__|__inline|extern)\s+', '', stmt, count=1)

            # Try function pointer typedef: typedef rettype (*name)(params)
            if m := re.match(
                r'^typedef\s+(?P<ret>.+?)\s*\(\s*\*\s*(?P<name>\w+)\s*\)\s*\((?P<params>.*)\)$',
                stmt,
            ):
                name = m.group('name')
                if name not in functions:
                    ret = normalize_type(m.group('ret'))
                    params = split_params(m.group('params'))
                    functions[name] = Proto(name=name, ret=ret, params=params, is_typedef=True)
                continue

            # Try simple typedef alias: typedef existing_name new_name
            if m := re.match(r'^typedef\s+(\w+)\s+(\w+)$', stmt):
                existing_name = m.group(1)
                new_name = m.group(2)
                typedef_aliases[new_name] = existing_name
                continue

            # Try regular function: rettype name(params)
            if m := re.match(
                r'^(?P<ret>[A-Za-z_][\w\s\*]*?[\w\*])\s*(?<=[\s\*])(?P<name>\w+)\s*\((?P<params>.*)\)$',
                stmt,
            ):
                name = m.group('name')
                ret = m.group('ret')
                params_str = m.group('params')

                # Ensure ret is not empty (reject macro calls like FOO(x))
                if not ret.strip():
                    continue

                if name not in functions:
                    ret = normalize_type(ret)
                    params = split_params(params_str)
                    functions[name] = Proto(name=name, ret=ret, params=params, is_typedef=False)

    # Resolve typedef aliases
    for new_name, existing_name in typedef_aliases.items():
        if existing_name in functions and new_name not in functions:
            # Copy the proto with the new name
            existing_proto = functions[existing_name]
            functions[new_name] = Proto(
                name=new_name,
                ret=existing_proto.ret,
                params=existing_proto.params,
                is_typedef=existing_proto.is_typedef,
            )

    return functions, macros


def parse_paramdef(pd):
    """Parse a single paramdef element and return list of Param objects."""
    parameters = pd.findall('parameter')

    if not parameters:
        # No parameter tags, just text content
        content = (pd.text or '').strip()
        if content in ('void', ''):
            return []
        if content in ('…', '...'):
            return [Param(type='', name='', varargs=True)]
        # If content is a single word (identifier), treat it as argument name (for macros)
        # Otherwise treat as type-only parameter
        if re.match(r'^\w+$', content):
            return [Param(type='', name=content)]
        else:
            return [Param(type=normalize_type(content), name='')]

    # Check for single <parameter>void</parameter>
    if len(parameters) == 1 and (parameters[0].text or '').strip() in ('void', ''):
        return []

    # Multiple parameters in one paramdef, e.g.:
    # <paramdef>sd_id128_t <parameter>id</parameter>, char <parameter>s</parameter>[static SD_ID128_STRING_MAX]</paramdef>
    # Also handle: <paramdef>int <parameter>fds[]</parameter></paramdef>
    params = []
    prev_type = (pd.text or '').strip()

    for i, param in enumerate(parameters):
        name_text = (param.text or '').strip()

        # Check if name contains array brackets (e.g., "fds[]")
        if name_arr_match := re.match(r'^(\w+)(\[[^\]]*\])+$', name_text):
            name = name_arr_match.group(1)
            arraydims_from_name = normalize_arr(name_text[len(name) :])
        else:
            name = name_text
            arraydims_from_name = ''

        # Parse tail: [arraydims], nexttype
        tail = param.tail or ''
        arraydims_from_tail = ''
        next_type = ''
        if arr_match := re.match(r'^\s*(?P<arr>(\[[^\]]*\])*)\s*(,(?P<rest>.*))?$', tail, re.DOTALL):
            arraydims_from_tail = normalize_arr(arr_match.group('arr') or '')
            next_type = (arr_match.group('rest') or '').strip()

        # Combine array dimensions from name and tail
        arraydims = arraydims_from_name + arraydims_from_tail

        ptype = normalize_type(prev_type)
        params += [Param(type=ptype, name=name, arraydims=arraydims)]

        prev_type = next_type

    return params


def parse_man(page):
    """Parse man page XML and extract function prototypes."""
    protos = []
    filename = os.path.basename(page)

    pagetree = tree.parse(page)
    root = pagetree.getroot()

    if root.tag != 'refentry':
        return protos

    for fp in root.findall('.//funcprototype'):
        funcdef = fp.find('funcdef')
        if funcdef is None:
            continue

        func = funcdef.find('function')
        funcdef_text = (funcdef.text or '').strip()

        # Determine if typedef
        is_typedef = funcdef_text.startswith('typedef')

        # Extract name and return type
        if func is not None:
            name = (func.text or '').strip()
            if is_typedef:
                # typedef rettype (*name)
                # funcdef.text is like "typedef int (*"
                ret = funcdef_text.replace('typedef', '', 1).replace('(*', '').strip()
            else:
                # Regular: rettype <function>name</function>
                ret = funcdef_text
        else:
            # No <function> tag, extract from funcdef.text
            # e.g., "int sd_bus_message_append_string_memfd"
            words = re.findall(r'\w+', funcdef_text)
            if not words:
                continue
            name = words[-1]
            ret = ' '.join(words[:-1])
            # Check for typedef with (*
            if 'typedef' in funcdef_text and '(*' in funcdef_text:
                is_typedef = True
                ret = re.sub(r'typedef', '', ret).replace('(*', '').strip()

        ret = normalize_type(ret)

        # Parse parameters
        params = []
        for pd in fp.findall('paramdef'):
            params.extend(parse_paramdef(pd))

        protos += [ManProto(name=name, ret=ret, params=params, is_typedef=is_typedef, filename=filename)]

    return protos


def compare_params(man_params, header_params):
    """Compare parameter lists and return list of differences."""
    diffs = []

    if len(man_params) != len(header_params):
        diffs += [f'parameter count: man={len(man_params)} header={len(header_params)}']
        return diffs

    for i, (mp, hp) in enumerate(zip(man_params, header_params)):
        if mp.varargs or hp.varargs:
            if not (mp.varargs and hp.varargs):
                diffs += [f'param {i}: varargs mismatch']
            continue

        if mp.type != hp.type:
            diffs += [f"param {i}: type mismatch: man='{mp.type}' header='{hp.type}'"]
        if mp.name != hp.name:
            diffs += [f"param {i}: name mismatch: man='{mp.name}' header='{hp.name}'"]
        if mp.arraydims != hp.arraydims:
            diffs += [f"param {i}: array dims mismatch: man='{mp.arraydims}' header='{hp.arraydims}'"]

    return diffs


def compare_params_with_macro(man_params, macro_param_names):
    """Compare man params with macro argument names (type is skipped).
    Returns list of differences."""
    diffs = []

    # Extract man param names, handling varargs
    man_names = []
    for mp in man_params:
        if mp.varargs:
            man_names += ['...']
        else:
            man_names += [mp.name]

    if len(man_names) != len(macro_param_names):
        diffs += [f'argument count: man={len(man_names)} macro={len(macro_param_names)}']
        return diffs

    for i, (man_name, macro_name) in enumerate(zip(man_names, macro_param_names)):
        if man_name != macro_name:
            diffs += [f"argument {i}: name mismatch: man='{man_name}' macro='{macro_name}'"]

    return diffs


def main():
    if len(sys.argv) < 2:
        print('Usage: check-man-prototypes.py <man-pages...>', file=sys.stderr)
        sys.exit(1)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    functions, macros = parse_headers(root)

    errors = {}
    total_protos = 0

    for page in sys.argv[1:]:
        man_protos = parse_man(page)
        total_protos += len(man_protos)

        for mp in man_protos:
            # Try functions first (full type checking)
            hp = functions.get(mp.name)
            if hp is not None:
                # Compare typedef status
                if mp.is_typedef != hp.is_typedef:
                    errors.setdefault(mp.filename, []).append(
                        f"{mp.name}: typedef mismatch: man={'typedef' if mp.is_typedef else 'function'} "
                        f"header={'typedef' if hp.is_typedef else 'function'}"
                    )

                # Compare return type
                if mp.ret != hp.ret:
                    errors.setdefault(mp.filename, []).append(
                        f"{mp.name}: return type mismatch: man='{mp.ret}' header='{hp.ret}'"
                    )

                # Compare parameters
                param_diffs = compare_params(mp.params, hp.params)
                for diff in param_diffs:
                    errors.setdefault(mp.filename, []).append(f'{mp.name}: {diff}')
                continue

            # Try macros (argument names only, skip types)
            macro = macros.get(mp.name)
            if macro is not None:
                # For macros, only compare argument names, skip types and return type
                param_diffs = compare_params_with_macro(mp.params, macro.param_names)
                for diff in param_diffs:
                    errors.setdefault(mp.filename, []).append(f'{mp.name} (macro): {diff}')
                continue

            # Not found in either functions or macros
            errors.setdefault(mp.filename, []).append(f'{mp.name}: not found in headers or macros')

    if errors:
        for filename in sorted(errors.keys()):
            for error in errors[filename]:
                print(f'{filename}: {error}', file=sys.stderr)
        print(f'\nTotal errors: {sum(len(v) for v in errors.values())}', file=sys.stderr)
        sys.exit(1)
    else:
        print(f'Checked {total_protos} prototypes, all OK', file=sys.stderr)
        sys.exit(0)


if __name__ == '__main__':
    main()
