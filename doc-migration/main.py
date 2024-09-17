# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import json
import argparse
from typing import List, Tuple
from db2rst import convert_xml_to_rst


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
    files_output_dir = os.path.join(output_dir, "")
    os.makedirs(files_output_dir, exist_ok=True)

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
    else:
        if specific_file:
            print('hi specific file')
            specific_file_path = os.path.join(dir, specific_file)
            if os.path.isfile(specific_file_path):
                files_to_process = [specific_file]
            else:
                print(f"Error: The file '{
                      specific_file}' does not exist in the directory '{dir}'.")
                return
        else:
            files_to_process = [f for f in os.listdir(
                dir) if f.endswith(".xml")]

    updated_errors = []
    updated_successes_with_unhandled_tags = []

    for filename in files_to_process:
        filepath = os.path.join(dir, filename)
        print('converting file: ', filename)
        try:
            unhandled_tags, error = convert_xml_to_rst(
                filepath, files_output_dir)
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
        except Exception as e:
            result = {
                "file": filename,
                "status": "error",
                "unhandled_tags": [],
                "error": str(e)
            }
            updated_errors.append(result)

    if not specific_file:
        if not errored:
            errors_file_path = os.path.join(output_dir, "errors.json")
            if os.path.exists(errors_file_path):
                with open(errors_file_path, 'r') as json_file:
                    existing_errors = json.load(json_file)
                updated_errors += [
                    entry for entry in existing_errors if entry['file'] not in files_to_process]
            update_json_file(errors_file_path, updated_errors)

        if not unhandled_only:
            successes_with_unhandled_tags_file_path = os.path.join(
                output_dir, "successes_with_unhandled_tags.json")
            if os.path.exists(successes_with_unhandled_tags_file_path):
                with open(successes_with_unhandled_tags_file_path, 'r') as json_file:
                    existing_successes_with_unhandled_tags = json.load(
                        json_file)
                updated_successes_with_unhandled_tags += [
                    entry for entry in existing_successes_with_unhandled_tags if entry['file'] not in files_to_process]
            update_json_file(successes_with_unhandled_tags_file_path,
                             updated_successes_with_unhandled_tags)


def main():
    parser = argparse.ArgumentParser(
        description="Process XML files and save results to a directory.")
    parser.add_argument(
        "--dir", type=str, help="Path to the directory containing XML files.", default="../man")
    parser.add_argument(
        "--output", type=str, help="Path to the output directory for results and log files.")
    parser.add_argument(
        "--file", type=str, help="If provided, the script will only process the specified file.", default=None)
    parser.add_argument("--errored", action='store_true',
                        help="Process only files listed in errors.json.")
    parser.add_argument("--unhandled-only", action='store_true',
                        help="Process only files listed in successes_with_unhandled_tags.json.")

    args = parser.parse_args()

    process_xml_files_in_directory(
        args.dir, args.output, args.file, args.errored, args.unhandled_only)


if __name__ == "__main__":
    main()
