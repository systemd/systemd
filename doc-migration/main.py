# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import json
import argparse
import shutil
from typing import List
from db2rst import convert_xml_to_rst

FILES_USED_FOR_INCLUDES = [
    'bpf-delegate.xml',
    'cgroup-sandboxing.xml',
    'common-variables.xml',
    'hostname.xml',
    'importctl.xml',
    'libsystemd-pkgconfig.xml',
    'org.freedesktop.locale1.xml',
    'sd_bus_add_match.xml',
    'sd_bus_message_append_basic.xml',
    'sd_bus_message_read_basic.xml',
    'sd_journal_get_data.xml',
    'standard-conf.xml',
    'standard-options.xml',
    'standard-specifiers.xml',
    'supported-controllers.xml',
    'system-only.xml',
    'system-or-user-ns.xml',
    'system-or-user-ns-mountfsd.xml',
    'systemctl.xml',
    'systemd-resolved.service.xml',
    'systemd.link.xml',
    'systemd.mount.xml',
    'systemd.netdev.xml',
    'systemd.service.xml',
    'tc.xml',
    'threads-aware.xml',
    'timedatectl.xml',
    'unit-states.xml',
    'user-system-options.xml',
    'vpick.xml',
]

INCLUDES_DIR = "includes"


def load_files_from_json(json_path: str) -> List[str]:
    """
    Loads a list of filenames from a JSON file.

    Parameters:
    json_path (str): Path to the JSON file.

    Returns:
    List[str]: List of filenames.
    """
    if not os.path.isfile(json_path):
        print(f"Error: The file '{json_path}' does not exist.")
        return []

    with open(json_path, 'r') as json_file:
        data = json.load(json_file)

    return [entry['file'] for entry in data]


def update_json_file(json_path: str, updated_entries: List[dict]) -> None:
    """
    Updates a JSON file with new entries.

    Parameters:
    json_path (str): Path to the JSON file.
    updated_entries (List[dict]): List of updated entries to write to the JSON file.
    """
    with open(json_path, 'w') as json_file:
        json.dump(updated_entries, json_file, indent=4)


def copy_non_xml_code_examples(src_dir: str, output_dir: str) -> None:
    """
    Copies non-XML files from src_dir into code-examples located one level above output_dir.
    Files with extensions c, sh, or py are placed into a subfolder named after the extension.
    All other non-XML files go directly under that code-examples directory.
    This includes a few of non-relevant files (meson.build etc), hopefully that
    has no adverse effects through other processes outside of /doc-migration.
    """
    out_abs = os.path.abspath(output_dir)
    parent_dir = os.path.dirname(out_abs)
    code_examples_base = os.path.join(parent_dir, "code-examples")
    os.makedirs(code_examples_base, exist_ok=True)

    for entry in os.listdir(src_dir):
        src_path = os.path.join(src_dir, entry)
        if not os.path.isfile(src_path):
            continue
        if entry.endswith(".xml"):
            continue

        suffix = entry.rsplit(".", 1)[-1].lower() if "." in entry else ""
        if suffix in {"c", "sh", "py"}:
            dest_dir = os.path.join(code_examples_base, suffix)
        else:
            dest_dir = code_examples_base

        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(src_path, os.path.join(dest_dir, entry))


def process_xml_files_in_directory(dir: str, output_dir: str, specific_file: str = None, errored: bool = False, unhandled_only: bool = False) -> None:
    """
    Processes all XML files in a specified directory, logs results to a JSON file.

    Parameters:
    dir (str): Path to the directory containing XML files.
    output_dir (str): Path to the JSON file for logging results.
    specific_file (str, optional): Specific XML file to process. Defaults to None.
    errored (bool, optional): Flag to process only files listed in errors.json. Defaults to False.
    unhandled_only (bool, optional): Flag to process only files listed in successes_with_unhandled_tags.json. Defaults to False.
    """
    files_output_dir = os.path.join(output_dir)
    includes_output_dir = os.path.join(output_dir, INCLUDES_DIR)
    os.makedirs(files_output_dir, exist_ok=True)
    os.makedirs(includes_output_dir, exist_ok=True)

    files_to_process = []

    if errored:
        errors_json_path = os.path.join(output_dir, "errors.json")
        files_to_process = load_files_from_json(errors_json_path)
        if not files_to_process:
            print("No files to process from errors.json. Exiting.")
            return
    elif unhandled_only:
        unhandled_json_path = os.path.join(
            output_dir, "successes_with_unhandled_tags.json")
        files_to_process = load_files_from_json(unhandled_json_path)
        if not files_to_process:
            print("No files to process from successes_with_unhandled_tags.json. Exiting.")
            return
    elif specific_file:
        specific_file_path = os.path.join(dir, specific_file)
        if os.path.isfile(specific_file_path):
            files_to_process = [specific_file]
        else:
            print(f"Error: The file '{
                  specific_file}' does not exist in the directory '{dir}'.")
            return
    else:
        files_to_process = [f for f in os.listdir(dir) if f.endswith(".xml")]

    errors_json_path = os.path.join(output_dir, "errors.json")
    unhandled_json_path = os.path.join(
        output_dir, "successes_with_unhandled_tags.json")

    existing_errors = []
    existing_unhandled = []

    if os.path.exists(errors_json_path):
        with open(errors_json_path, 'r') as json_file:
            existing_errors = json.load(json_file)

    if os.path.exists(unhandled_json_path):
        with open(unhandled_json_path, 'r') as json_file:
            existing_unhandled = json.load(json_file)

    updated_errors = []
    updated_successes_with_unhandled_tags = []

    for filename in files_to_process:
        filepath = os.path.join(dir, filename)
        # output_subdir = includes_output_dir if filename in FILES_USED_FOR_INCLUDES else files_output_dir
        # No longer put includes in a separate folder, this makes nested
        # includes needlessly complicated
        output_subdir = files_output_dir
        # print('converting file: ', filename)
        try:
            if filename != 'directives-template.xml':
                unhandled_tags, error = convert_xml_to_rst(filepath, output_subdir)
                if error:
                    result = {
                        "file": filename,
                        "status": "error",
                        "unhandled_tags": unhandled_tags,
                        "error": error
                    }
                    updated_errors.append(result)
                else:
                    result = {
                        "file": filename,
                        "status": "success",
                        "unhandled_tags": unhandled_tags,
                        "error": error
                    }
                    if len(unhandled_tags) > 0:
                        updated_successes_with_unhandled_tags.append(result)

                existing_errors = [
                    entry for entry in existing_errors if entry['file'] != filename]
                existing_unhandled = [
                    entry for entry in existing_unhandled if entry['file'] != filename]

        except Exception as e:
            result = {
                "file": filename,
                "status": "error",
                "unhandled_tags": [],
                "error": str(e)
            }
            updated_errors.append(result)

    if not errored:
        updated_errors += existing_errors

    if not unhandled_only:
        updated_successes_with_unhandled_tags += existing_unhandled

    update_json_file(errors_json_path, updated_errors)
    update_json_file(unhandled_json_path,
                     updated_successes_with_unhandled_tags)


def main():
    parser = argparse.ArgumentParser(
        description="Process XML files and save results to a directory.")
    parser.add_argument(
        "--dir", type=str, help="Path to the directory containing XML files.", default="../man")
    parser.add_argument(
        "--output", type=str, help="Path to the output directory for results and log files.", default="in-progress")
    parser.add_argument(
        "--file", type=str, help="If provided, the script will only process the specified file.", default=None)
    parser.add_argument("--errored", action='store_true',
                        help="Process only files listed in errors.json.")
    parser.add_argument("--unhandled-only", action='store_true',
                        help="Process only files listed in successes_with_unhandled_tags.json.")

    args = parser.parse_args()

    process_xml_files_in_directory(
        args.dir, args.output, args.file, args.errored, args.unhandled_only)
    copy_non_xml_code_examples(args.dir, args.output)


if __name__ == "__main__":
    main()
