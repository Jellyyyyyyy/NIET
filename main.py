import argparse
from datetime import datetime
import json
import logging
import os
import sys
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from NessusAPI import NessusAPI
from nessus_combine import nessus_combine
from nessus_import import nessus_import
from nessus_export import nessus_export
from nessus_convert import nessus_convert
from utils import get_ascii_art, get_authors, get_non_blank_input, get_user_confirmation, get_user_input_with_default

urllib3.disable_warnings(InsecureRequestWarning)


def parse_args(logger):
    parser = argparse.ArgumentParser(description="Nessus Import/Export Tool")
    
    mode = parser.add_mutually_exclusive_group(required=False)
    
    mode.add_argument("-i", "--import", dest="import_mode", action="store_true",
                        help="Import mode")
    mode.add_argument("-e", "--export", dest="export_mode", action="store_true",
                        help="Export mode")
    mode.add_argument("-c", "--convert", dest="convert_mode", action="store_true",
                        help="Convert mode")
    mode.add_argument("-x", "--combine", dest="combine_mode", action="store_true",
                        help="Combine mode")
    
    nessus_args_group = parser.add_argument_group("Settings for Nessus Server")
    
    nessus_args_group.add_argument("-u", "--nessus-url",
                                    help="Base URL of the Nessus server (e.g. https://localhost:8834)")
    nessus_args_group.add_argument("-a", "--api-token",
                                    help="API token to use, if not supplied, will attempt to get automatically. Read README on how to obtain an API token manually.")
    
    general_args_group = parser.add_argument_group("General Settings")
    
    general_args_group.add_argument("-s", "--secure", action="store_true",
                                    help="Enables SSL verification (default: False); Nessus usually uses self-signed certificates, so insecure mode is usually safe to use.")
    general_args_group.add_argument("-v", "--verbose", action="store_true",
                                    help="Enable verbose (debug) logging")
    general_args_group.add_argument("-t", "--threads", type=int, default=1,
                                    help="Number of threads to use for exporting scans (default: 1)")
    general_args_group.add_argument("-k", "--config", default=None,
                                    help="Path to a configuration file to use for the script.")
    general_args_group.add_argument("-d", "--directory",
                                    help="Directory containing .nessus files. Used for import and combine modes.")
    general_args_group.add_argument("-N", "--no-recursive", action="store_false",
                                    help="Do not recursively search for .nessus files.")
    general_args_group.add_argument("-f", "--filepaths", nargs="*",
                                    help="List of .nessus filepaths. Used for import and combine modes.")
    general_args_group.add_argument("-o", "--output",
                                    help="Output file path. Used for export and combine modes.")
    general_args_group.add_argument("--csv", 
                                    help="CSV File path. Used in Export and Convert modes.")
    
    # Import mode arguments.
    import_args_group = parser.add_argument_group("Import mode Settings")
    import_args_group.add_argument("-F", "--upload-folder", default=None,
                                    help="Name of the folder to upload scans into. If not provided, you'll be prompted.")
    
    # Export mode arguments.
    export_args_group = parser.add_argument_group("Export mode Settings")
    export_args_group.add_argument("--excel", 
                                    help="Outputs an Excel file on top of the CSV file with formatting and various sheet tabs.")

    # Convert mode arguments.
    convert_args_group = parser.add_argument_group("Convert mode Settings")
    convert_args_group.add_argument("-X", "--software-exclusion-keywords",
                                    help="Comma-separated list of keywords to exclude from the Installed Software sheet.")
    convert_args_group.add_argument("-C", "--excel-config-path",
                                    help="Path to a configuration file to use for Excel output. (e.g. /path/to/config.json)")
    
    # Combine mode arguments.
    combine_args_group = parser.add_argument_group("Combine mode Settings")
    combine_args_group.add_argument("-R", "--remove-duplicates", default="ask",
                                    help="Remove duplicates from the merged scan. Modes: 'Ask' or 'Auto'")
    combine_args_group.add_argument("--scan-name", required=False, default="Merged Scan",
                                    help="New name for the merged scan. Allowed characters: alphanumeric, underscores, spaces, dashes.")
    


    args = parser.parse_args()
    
    print(get_authors())
    print(get_ascii_art())
    
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
            mode = config.get("mode")
            
            if mode in ["import", "i", "im", "import mode"]:
                args.import_mode = True
            elif mode in ["export", "e", "ex", "export mode"]:
                args.export_mode = True
            elif mode in ["convert", "c", "con", "convert mode"]:
                args.convert_mode = True
            elif mode in ["combine", "x", "com", "combine mode"]:
                args.combine_mode = True
            
            # General settings
            args.nessus_url = config.get("nessus_url")
            args.api_token = config.get("api_token")
            args.username = config.get("username")
            args.password = config.get("password")
            args.secure = config.get("secure")
            args.verbose = config.get("verbose")
            args.threads = config.get("threads")
            args.directory = config.get("directory")
            args.filepaths = config.get("filepaths")
            args.output = config.get("output")
            args.csv = config.get("csv")
            
            # Import mode settings
            args.no_recursive = config.get("no_recursive")
            args.upload_folder = config.get("upload_folder")
            
            # Export mode settings
            args.excel = config.get("excel")
            
            # Convert mode settings
            args.software_exclusion_keywords = config.get("software_exclusion_keywords")
            args.excel_config_path = config.get("excel_config_path")
            
            # Combine mode settings
            args.remove_duplicates = config.get("remove_duplicates", "ask")
            args.scan_name = config.get("scan_name", f"Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}")
            
            if type(args.software_exclusion_keywords) == list:
                args.software_exclusion_keywords = ",".join(args.software_exclusion_keywords)

    if not args.import_mode and not args.export_mode and not args.convert_mode and not args.combine_mode:
        while True:
            mode = get_non_blank_input("Would you like to Import (I) / Export (E) / Combine (X) Nessus scans or Convert (C) a Nessus CSV to Excel? (I/E/X/C): ", logger=logger).strip().lower()
            if mode in ["import", "i", "im", "import mode"]:
                args.import_mode = True
                break
            elif mode in ["export", "e", "ex", "export mode"]:
                args.export_mode = True
                break
            elif mode in ["convert", "c", "con", "convert mode"]:
                args.convert_mode = True
                break
            elif mode in ["combine", "x", "com", "combine mode"]:
                args.combine_mode = True
                break
            else:
                logger.error("Not a valid option. Please select either import, export, convert or combine (I/E/C/X): ")
            
    if args.import_mode or args.export_mode:
        if not args.nessus_url:
            args.nessus_url = get_user_input_with_default("Enter the Nessus server URL (e.g. https://localhost:8834) [https://localhost:8834]: ", logger=logger, default="https://localhost:8834")
        if not (args.nessus_url.startswith("http://") or args.nessus_url.startswith("https://")):
            args.nessus_url = "https://" + args.nessus_url
        
    if args.import_mode and not args.directory and not args.filepaths:
        args.directory = get_user_input_with_default("Enter the directory containing .nessus files (e.g. /path/to/directory/with/nessus/files) [CURRENT DIRECTORY]: ", logger=logger, default=os.getcwd())
    if args.import_mode and (not os.path.isdir(args.directory) or not args.filepaths):
        logger.error(f"Error: Directory '{args.directory}' does not exist.")
        sys.exit(1)
        
    if args.export_mode and not args.csv:
        args.csv = get_user_input_with_default("What do you want to name the output CSV file? (e.g. output.csv) [output.csv]: ", logger=logger, default="output.csv")
        if not args.csv.lower().endswith('.csv'):
            args.csv += '.csv'
        
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
        
    if args.combine_mode and not args.directory and not args.filepaths:
        args.directory = get_user_input_with_default("Enter the directory containing .nessus files (e.g. /path/to/directory/with/nessus/files) [CURRENT DIRECTORY]: ", logger=logger, default=os.getcwd())
        if args.import_mode and (not os.path.isdir(args.directory) or not args.filepaths):
            logger.error(f"Error: Directory '{args.directory}' does not exist.")
            sys.exit(1)
        
    if args.combine_mode:
        if not args.output:
            args.output = get_user_input_with_default("What do you want to name the output Nessus file? (e.g. output.nessus) [output.nessus]: ", logger=logger, default="output.nessus")
        if not args.scan_name:
            args.scan_name = get_user_input_with_default(f"What do you want to name the merged scan? (e.g. Merged Scan) [Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}]: ", logger=logger, default=f"Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        if args.output:
            if not args.output.lower().endswith('.nessus'):
                args.output += '.nessus'
        
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
        if get_user_confirmation("Would you like to attempt toget an API token automatically? (Y/n): ", default=True):
            if not nessus_api.get_api_token_automatically():
                logger.error("Failed to get API token automatically. Please enter your API token manually")

        if not nessus_api.get_api_token():
            args.api_token = get_non_blank_input("Enter your Nessus API token (e.g. e306e373-8ed6-4d01-b413-299e02037e5f): ", logger=logger)
    
    if not nessus_api.set_session_headers():
        sys.exit(1)
    
    if args.import_mode:
        nessus_import(nessus_api, args.directory, args)
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

