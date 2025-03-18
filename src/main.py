import argparse
from datetime import datetime
import json
import logging
import os
import sys
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from utils.NessusAPI import NessusAPI
from modes.combine import nessus_combine
from modes.iport import nessus_import
from modes.eport import nessus_export
from modes.convert import nessus_convert
from utils.helper import check_min_nessus_files, get_ascii_art, get_authors, get_non_blank_input, get_user_confirmation, get_user_input_with_default

urllib3.disable_warnings(InsecureRequestWarning)


def add_mode_arguments(parser):
    """Add mutually exclusive mode arguments."""
    mode = parser.add_mutually_exclusive_group(required=False)
    modes = {
        "-i": ("--import", "import_mode", "Import mode"),
        "-e": ("--export", "export_mode", "Export mode"),
        "-c": ("--convert", "convert_mode", "Convert mode"),
        "-x": ("--combine", "combine_mode", "Combine mode"),
    }
    for short, (long, dest, help_text) in modes.items():
        mode.add_argument(short, long, dest=dest, action="store_true", help=help_text)
        
        
def add_nessus_arguments(parser):
    """Add arguments for Nessus server settings."""
    nessus_group = parser.add_argument_group("Nessus Server Settings")
    nessus_group.add_argument("-u", "--nessus-url", help="Base URL of the Nessus server")
    nessus_group.add_argument("-a", "--api-token", help="API token for authentication")
    nessus_group.add_argument("-s", "--secure", action="store_true", help="Enable SSL verification")
    

def add_general_arguments(parser):
    """Add general arguments applicable to all modes."""
    general_group = parser.add_argument_group("General Settings")
    general_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    general_group.add_argument("-t", "--threads", type=int, default=1, help="Number of threads")
    general_group.add_argument("-k", "--config", help="Path to configuration file")
    general_group.add_argument("-d", "--directory", help="Directory containing .nessus files")
    general_group.add_argument("-N", "--no-recursive", action="store_false", help="Disable recursive search")
    general_group.add_argument("-f", "--filepaths", nargs="*", help="List of .nessus filepaths")
    general_group.add_argument("-o", "--output", help="Output file path")
    general_group.add_argument("--csv", help="CSV file path")


def add_mode_specific_arguments(parser):
    """Add mode-specific arguments for import, export, convert, and combine modes."""
    import_group = parser.add_argument_group("Import Mode Settings")
    import_group.add_argument("--upload-folder", help="Folder name for scan uploads")

    export_group = parser.add_argument_group("Export Mode Settings")
    export_group.add_argument("--excel", nargs="?", const=True, 
                              help="Enables outputing an Excel file on top of the CSV. Specify the filepath with this flag or in the prompts.")

    convert_group = parser.add_argument_group("Convert Mode Settings")
    convert_group.add_argument("--software-exclusion-keywords", help="Keywords to exclude")
    convert_group.add_argument("--excel-config-path", help="Path to Excel config file")

    combine_group = parser.add_argument_group("Combine Mode Settings")
    combine_group.add_argument("--remove-duplicates", default=None, choices=["ask", "auto"], help="Remove duplicate scans")
    combine_group.add_argument("--scan-name", help="Name for merged scan")
    combine_group.add_argument("--no-upload", action="store_true", help="Skip upload after merging")
    combine_group.add_argument("--compliance", default=None, choices=["remove", "inject", "ignore"], help="What to do if compliance is not found in a Report Host")
    combine_group.add_argument("--compliance-path", help="Path to compliance file")


def load_config(args):
    """Load settings from a configuration file."""
    if not args.config:
        return

    with open(args.config, 'r') as f:
        config = json.load(f)

    # Map string mode names to arguments
    mode_mapping = {
        "import": "import_mode",
        "export": "export_mode",
        "convert": "convert_mode",
        "combine": "combine_mode"
    }
    
    if "mode" in config:
        mode_key = config["mode"].lower()
        if mode_key in mode_mapping:
            setattr(args, mode_mapping[mode_key], True)

    # Load other configurations dynamically
    for key, value in config.items():
        if hasattr(args, key):
            setattr(args, key, value)
            
    if args.software_exclusion_keywords and type(args.software_exclusion_keywords) == list:
        args.software_exclusion_keywords = ",".join(args.software_exclusion_keywords)


def prompt_user_for_missing_args(args, logger):
    mode_map = {
        "i": "import_mode",
        "e": "export_mode",
        "c": "convert_mode",
        "x": "combine_mode"
    }

    if not any(getattr(args, mode, False) for mode in mode_map.values()):
        while True:
            mode_input = get_non_blank_input("Select mode: Import (I) / Export (E) / Convert (C) / Combine (X): ", logger=logger).strip().lower()
            if mode_input in mode_map:
                setattr(args, mode_map[mode_input], True)
                break
            logger.error("Invalid option. Please choose I, E, C, or X.")
            
    if args.import_mode or args.export_mode:
        while True:
            if not args.nessus_url:
                args.nessus_url = get_user_input_with_default("Enter the Nessus Web Server URL (e.g. https://localhost:8834) [https://localhost:8834]: ", logger=logger, default="https://localhost:8834")
            if not (args.nessus_url.startswith("http://") or args.nessus_url.startswith("https://")):
                args.nessus_url = "https://" + args.nessus_url
            
            logger.info(f"Checking connection to {args.nessus_url}")
            if not NessusAPI.check_connection_from_url(args.nessus_url, args.secure):
                logger.error("Failed to connect to the Nessus server. Please check your Nessus URL")
                args.nessus_url = None
            else:
                logger.info(f"Connection to {args.nessus_url} successful")
                break
        
    if args.import_mode or args.combine_mode:
        while True:
            # --- Ask the user to choose input type if neither exists ---
            if args.directory is None and args.filepaths is None:
                choice = get_user_input_with_default(
                    "Would you like to specify a Directory (D) or Filepaths (F)? [Directory]: ",
                    logger=logger, default="directory").lower().strip()
                if choice in ["d", "directory"]:
                    dir_input = get_user_input_with_default(
                        "Enter the directory containing .nessus files [CURRENT DIRECTORY]: ",
                        logger=logger, default=os.getcwd()).strip()
                    args.directory = dir_input if dir_input != "" else None
                elif choice in ["f", "filepaths", "f"]:
                    logger.info("You may enter one or more filepaths separated by semicolons (;).")
                    filepaths = []
                    while True:
                        user_input = get_user_input_with_default(
                            "Enter filepath(s) (or press Enter on a blank line to finish): ",
                            logger=logger, default="").strip()
                        if user_input == "":
                            break
                        # Split on semicolons so that filepaths with spaces are allowed.
                        new_fps = [s.strip() for s in user_input.split(';') if s.strip()]
                        filepaths.extend(new_fps)
                    args.filepaths = filepaths if filepaths else None
                else:
                    logger.error("Invalid option. Please choose Directory or Filepaths.")
                    continue

            # --- Validate and correct directory if provided ---
            if args.directory is not None:
                while True:
                    if not os.path.isdir(args.directory):
                        logger.error(f"Directory '{args.directory}' does not exist.")
                        new_dir = get_user_input_with_default(
                            "Please enter a valid directory (or press Enter to skip): ",
                            logger=logger, default="").strip()
                        if new_dir == "":
                            args.directory = None
                            break
                        else:
                            args.directory = new_dir
                            continue  # Re-check the new directory.
                    else:
                        # Directory exists; ensure it has enough .nessus files.
                        required_files = 1 if args.import_mode else 2
                        if not check_min_nessus_files(args.directory, min_files=required_files, recursive=args.no_recursive):
                            logger.error(f"Directory '{args.directory}' does not contain at least {required_files} Nessus file{'s' if required_files > 1 else ''}.")
                            new_dir = get_user_input_with_default(
                                "Please enter a valid directory (or press Enter to skip): ",
                                logger=logger, default="").strip()
                            if new_dir == "":
                                args.directory = None
                                break
                            else:
                                args.directory = new_dir
                                continue  # Re-check the new directory.
                        break  # Valid directory found.

            # --- Validate and correct filepaths if provided ---
            if args.filepaths is not None:
                collected_filepaths = []
                for fp in args.filepaths:
                    # Validate existence and extension.
                    if not os.path.isfile(fp):
                        logger.error(f"File '{fp}' does not exist.")
                        while True:
                            new_fp = get_user_input_with_default(
                                f"Enter a correct filepath for '{fp}' (or press Enter to skip): ",
                                logger=logger, default="").strip()
                            if new_fp == "":
                                break  # Skip this file.
                            if not os.path.isfile(new_fp):
                                logger.error(f"File '{new_fp}' does not exist.")
                                continue
                            if not new_fp.lower().endswith('.nessus'):
                                logger.error(f"File '{new_fp}' does not have a .nessus extension.")
                                continue
                            collected_filepaths.append(new_fp)
                            break
                    elif not fp.lower().endswith('.nessus'):
                        logger.error(f"File '{fp}' does not have a .nessus extension.")
                        while True:
                            new_fp = get_user_input_with_default(
                                f"Enter a correct filepath for '{fp}' (or press Enter to skip): ",
                                logger=logger, default="").strip()
                            if new_fp == "":
                                break
                            if not new_fp.lower().endswith('.nessus'):
                                logger.error(f"File '{new_fp}' does not have a .nessus extension.")
                                continue
                            if not os.path.isfile(new_fp):
                                logger.error(f"File '{new_fp}' does not exist.")
                                continue
                            collected_filepaths.append(new_fp)
                            break
                    else:
                        collected_filepaths.append(fp)

                # Remove duplicates (comparing absolute paths).
                unique_filepaths = []
                seen = set()
                for fp in collected_filepaths:
                    abs_fp = os.path.abspath(fp)
                    if abs_fp in seen:
                        logger.info(f"Duplicate file '{fp}' detected; skipping duplicate.")
                        continue
                    seen.add(abs_fp)
                    unique_filepaths.append(fp)
                # If a valid directory exists, remove filepaths that refer to files within it.
                if args.directory:
                    abs_dir = os.path.abspath(args.directory)
                    filtered = []
                    for fp in unique_filepaths:
                        abs_fp = os.path.abspath(fp)
                        if os.path.commonpath([abs_fp, abs_dir]) == abs_dir:
                            logger.info(f"File '{fp}' is within the specified directory; skipping it from filepaths.")
                        else:
                            filtered.append(fp)
                    unique_filepaths = filtered

                args.filepaths = unique_filepaths if unique_filepaths else None

            # --- Final check: ensure at least one valid source is provided ---
            if args.directory is not None:
                # The directory is valid.
                break
            elif args.filepaths is not None:
                if (args.import_mode and len(args.filepaths) >= 1) or (args.combine_mode and len(args.filepaths) >= 2):
                    break
                else:
                    logger.error("Insufficient number of valid filepaths provided.")
                    extra = get_user_input_with_default(
                        "Enter additional filepath(s) separated by semicolons (or press Enter to finish): ",
                        logger=logger, default="").strip()
                    if extra:
                        extra_fps = [s.strip() for s in extra.split(';') if s.strip()]
                        if args.filepaths is None:
                            args.filepaths = extra_fps
                        else:
                            args.filepaths.extend(extra_fps)
                    else:
                        args.filepaths = None
            else:
                logger.error("No valid directory or filepaths provided.")
        # End of while loop for file/directory input
                
            
    if args.export_mode and not args.csv:
        args.csv = get_user_input_with_default("What do you want to name the output CSV file? (e.g. output.csv) [output.csv]: ", logger=logger, default="output.csv")
        if not args.csv.lower().endswith('.csv'):
            args.csv += '.csv'
            
    if args.export_mode and args.excel is True:
        args.excel = get_user_input_with_default("What do you want to name the output Excel file? (e.g. output.xlsx) [output.xlsx]: ", logger=logger, default="output.xlsx")
        if not args.excel.lower().endswith('.xlsx'):
            args.excel += '.xlsx'
        

    if args.convert_mode and not args.csv:
        args.csv = get_non_blank_input("What is the filepath of the CSV file to convert to Excel (e.g. /path/to/file.csv): ", logger=logger)
        
    if args.convert_mode and not os.path.isfile(args.csv):
        logger.error(f"Error: File '{args.csv}' does not exist.")
        sys.exit(1)
        
    if args.convert_mode and not args.output:
        args.output = get_user_input_with_default("What do you want to name the output Excel file? (e.g. output.xlsx) [output.xlsx]: ", logger=logger, default="output.xlsx")
        if not args.output.lower().endswith('.xlsx'):
            args.output += '.xlsx'
        
    if args.convert_mode and args.software_exclusion_keywords:
        args.software_exclusion_keywords = args.software_exclusion_keywords.split(",")
        if args.software_exclusion_keywords == [""]:
            args.software_exclusion_keywords = None
            
    if args.convert_mode and not args.excel_config_path:
        args.excel_config_path = None
        
    if args.combine_mode:
        if not args.output:
            args.output = get_user_input_with_default("What do you want to name the output Nessus file? (e.g. output.nessus) [output.nessus]: ", logger=logger, default="output.nessus")
        
        if args.output:
            if not args.output.lower().endswith('.nessus'):
                args.output += '.nessus'
                
        if not args.scan_name:
            args.scan_name = get_user_input_with_default(f"What do you want to name the merged scan? (e.g. Merged Scan) [Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}]: ", logger=logger, default=f"Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        if args.compliance_path and not os.path.isfile(args.compliance_path):
            logger.error(f"Error: File '{args.compliance_path}' does not exist.")
            args.compliance_path = get_user_input_with_default(f"Specify a different compliance file (or press Enter to skip): ", logger=logger, default=None)


def parse_args(logger):
    """Main function to parse arguments and handle config files."""
    parser = argparse.ArgumentParser(description="Nessus Import/Export Tool")

    # Add argument groups
    add_mode_arguments(parser)
    add_nessus_arguments(parser)
    add_general_arguments(parser)
    add_mode_specific_arguments(parser)

    args = parser.parse_args()

    print(get_authors())
    print(get_ascii_art())

    # Load config file if provided
    load_config(args)

    # Prompt user for missing arguments
    prompt_user_for_missing_args(args, logger)

    return args


def main():
    # Set up logging.
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logger = logging.getLogger(__name__)

    args = parse_args(logger)
    
    if args.verbose:
        logger.info("Verbose logging enabled")
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    if args.convert_mode:
        nessus_convert(args.csv, args.output, logger, args.software_exclusion_keywords, None, args.excel_config_path)
        return
    
    if args.combine_mode:
        nessus_combine(args.output, args.scan_name, args.directory, args.filepaths, logger, args)
        
        if not get_user_confirmation("Would you like to import the combined Nessus file into Nessus? (y/N): ", default=False):
            return
        
        args.combine_mode = False
        args.import_mode = True
        args.filepaths = [args.output]
        args.directory = None
        prompt_user_for_missing_args(args, logger)

    nessus_api = NessusAPI(args.nessus_url.rstrip('/'), args.api_token, verify=args.secure, logger=logger)
    
    if not nessus_api.check_connection():
        logger.error("Failed to connect to the Nessus server. Please check your Nessus URL")
        sys.exit(1)
    
    # Allow up to 3 login attempts.
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        if args.config:
            if args.username:
                username = args.username
            else:
                username = get_non_blank_input("Enter your Nessus username: ", logger=logger)
                
            if args.password:
                password = args.password
            else:
                password = get_non_blank_input("Enter your Nessus password: ", password=True, logger=logger)
                
        else:
            username = get_non_blank_input("Enter your Nessus username: ", logger=logger)
            password = get_non_blank_input("Enter your Nessus password: ", password=True, logger=logger)
        
        nessus_api.set_credentials(username, password)
        token = nessus_api.login_nessus()
        
        if token:
            nessus_api.set_token(token)
            logger.info("Login successful. Proceeding...")
            break
        else:
            if attempt == max_attempts:
                logger.error(f"Login failed after {max_attempts} attempts")
                sys.exit(1)
            else:
                logger.error(f"Login attempt {attempt}/{max_attempts} failed. Please try again")
                
                if args.config and args.username and args.password:
                    if get_user_confirmation("Would you like to enter your credentials manually? (Y/n): ", default=True):
                        args.username = get_non_blank_input("Enter your Nessus username: ", logger=logger)
                        args.password = get_non_blank_input("Enter your Nessus password: ", password=True, logger=logger)
                elif args.config and args.username:
                    if get_user_confirmation("Would you like to enter your username manually? (Y/n): ", default=True):
                        args.username = get_non_blank_input("Enter your Nessus username: ", logger=logger)
                elif args.config and args.password:
                    if get_user_confirmation("Would you like to enter your password manually? (Y/n): ", default=True):
                        args.password = get_non_blank_input("Enter your Nessus password: ", password=True, logger=logger)
                

    if (args.import_mode or args.export_mode) and not args.api_token:
        if get_user_confirmation("Would you like to attempt to get an API token automatically? (Y/n): ", default=True):
            if not nessus_api.get_api_token_automatically():
                logger.error("Failed to get API token automatically. Please enter your API token manually")

        if not nessus_api.get_api_token():
            args.api_token = get_non_blank_input("Enter your Nessus API token (e.g. e306e373-8ed6-4d01-b413-299e02037e5f): ", logger=logger)
    
    if not nessus_api.set_session_headers():
        sys.exit(1)
    
    if args.import_mode:
        nessus_import(nessus_api, args.directory, args.filepaths, args)
    elif args.export_mode:
        nessus_export(nessus_api, args.csv, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

