# This file does preprocessing before Sphinx is run on the rst files.

# Its main purpose is global variable replacement. While there are several
# ways to achieve this in Sphinx (global_substitutions extension or the
# rst_prolog replacements feature of Sphinx), these cannot handle substitutions
# _within_ other formatting, because rst does not support nested inline markup.

# This file will take all global variables from the `global_substitutions` in
# conf.py and apply them to the rst files before they get handed to Sphinx.
# This way, we can have formatted, globally substituted variables.

#!/usr/bin/env python3
import os
import sys
import shutil
import importlib.util

def load_conf_py(conf_path: str):
    """Dynamically import a Sphinx conf.py file."""
    spec = importlib.util.spec_from_file_location("conf", conf_path)
    conf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conf)
    return conf

def copy_and_replace(src_dir: str, dst_dir: str, variables: dict):
    """Copy the full directory and perform replacements only in .rst files."""
    if os.path.exists(dst_dir):
        shutil.rmtree(dst_dir)
    shutil.copytree(src_dir, dst_dir)

    print('--------------------------------------------------------------------')

    replaced_files = 0
    total_files = 0
    for root, _, files in os.walk(dst_dir):
        for name in files:
            if not name.endswith(".rst"):
                continue
            total_files += 1
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8") as f:
                original_text = f.read()
            new_text = original_text
            for key, val in variables.items():
                new_text = new_text.replace(f'|{key}|', str(val))
            if new_text != original_text:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new_text)
                replaced_files += 1
                print(f'RST Preprocessor: Replaced vars in {name}')

    print('--------------------------------------------------------------------')
    print('Preprocessing complete:')
    print(f"- Processed {total_files} .rst file(s), performed substitutions in {replaced_files} file(s).")

def main():
    if len(sys.argv) != 4:
        print("Usage: preprocess_rst.py <source_dir> <conf_py_path> <output_dir>")
        sys.exit(1)

    src_dir, conf_py_path, dst_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    conf = load_conf_py(conf_py_path)

    if not hasattr(conf, "global_substitutions"):
        print("Error: conf.py must define a global_substitutions dict.")
        sys.exit(1)

    copy_and_replace(src_dir, dst_dir, conf.global_substitutions)
    print(f"- Processed {len(conf.global_substitutions)} substitutions from conf.py.")
    print('--------------------------------------------------------------------')

if __name__ == "__main__":
    main()
