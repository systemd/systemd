import os
import json
import argparse
from typing import List, Tuple
from db2rst import convert_xml_to_rst


def process_xml_files_in_directory(dir: str, output_dir: str, specific_file: str = None) -> None:
    """
    Processes all XML files in a specified directory, logs results to a JSON file.

    Parameters:
    directory (str): Path to the directory containing XML files.
    output_dir (str): Path to the JSON file for logging results.
    """
    errors = []
    successes_with_unhandled_tags = []

    os.makedirs(output_dir, exist_ok=True)

    files_to_process = []

    if specific_file:
        specific_file_path = os.path.join(dir, specific_file)
        if os.path.isfile(specific_file_path):
            files_to_process.append(specific_file)
        else:
            print(f"Error: The file '{
                  specific_file}' does not exist in the directory '{dir}'.")
            return
    else:
        files_to_process = [f for f in os.listdir(dir) if f.endswith(".xml")]

    for filename in files_to_process:
        if filename.endswith(".xml"):
            filepath = os.path.join(dir, filename)
            print('converting file: ', filename)
            try:
                unhandled_tags, error = convert_xml_to_rst(
                    filepath, output_dir)
                if error:
                    result = {
                        "file": filename,
                        "status": "error",
                        "unhandled_tags": unhandled_tags,
                        "error": error
                    }
                    errors.append(result)
                else:
                    result = {
                        "file": filename,
                        "status": "success",
                        "unhandled_tags": unhandled_tags,
                        "error": error
                    }
                    if len(unhandled_tags) > 0:
                        successes_with_unhandled_tags.append(result)
            except Exception as e:
                result = {
                    "file": filename,
                    "status": "error",
                    "unhandled_tags": [],
                    "error": str(e)
                }
                errors.append(result)

    # Save the results to three separate JSON files
    errors_file_path = os.path.join(output_dir, "errors.json")
    with open(errors_file_path, 'w') as json_file:
        json.dump(errors, json_file, indent=4)

    successes_with_unhandled_tags_file_path = os.path.join(
        output_dir, "successes_with_unhandled_tags.json")
    with open(successes_with_unhandled_tags_file_path, 'w') as json_file:
        json.dump(successes_with_unhandled_tags, json_file, indent=4)


def main():
    parser = argparse.ArgumentParser(
        description="Process XML files and save results to a directory.")
    parser.add_argument("--dir", type=str,
                        help="Path to the directory containing XML files.")
    parser.add_argument("--output", type=str,
                        help="Path to the output directory for results and log files.")
    parser.add_argument("--file", type=str,
                        help="If provided the script will only process the file provided", default=None)

    args = parser.parse_args()

    process_xml_files_in_directory(args.dir, args.output, args.file)


if __name__ == "__main__":
    main()
