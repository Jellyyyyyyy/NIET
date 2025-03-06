import argparse
import json
import logging
import os
import sys
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from NessusAPI import NessusAPI
from nessus_import import nessus_import
from nessus_export import nessus_export
from nessus_convert import nessus_convert
from utils import get_ascii_art, get_non_blank_input, get_user_confirmation, get_user_input_with_default

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
    
    # Import mode arguments.
    import_args_group = parser.add_argument_group("Import mode Settings")
    import_args_group.add_argument("-D", "--directory",
                        help="Directory containing .nessus files to import.")
    import_args_group.add_argument("-N", "--no-recursive", action="store_false",
                        help="Do not recursively search for .nessus files.")
    import_args_group.add_argument("-F", "--upload-folder", default=None,
                        help="Name of the folder to upload scans into. If not provided, you'll be prompted.")
    
    # Export mode arguments.
    export_args_group = parser.add_argument_group("Export mode Settings")
    export_args_group.add_argument("-C", "--csv", 
                                   help="Directly specify the merged output CSV file. If the file exists, you'll be prompted to overwrite, append or cancel.")
    export_args_group.add_argument("-E", "--excel", 
                                   help="Converts the output CSV file into an Excel file with separated sheets for Hosts, Vulnerabilities, Compliance, Open Ports, Users, and Installed Software.")

    # Convert mode arguments.
    convert_args_group = parser.add_argument_group("Convert mode Settings")
    convert_args_group.add_argument("-T", "--csv-path", 
                                   help="Filepath of the CSV file to convert to Excel")
    convert_args_group.add_argument("-X", "--output-excel", 
                                   help="Name of Excel file to output")
    convert_args_group.add_argument("-S", "--software-exclusion-keywords",
                                   help="Comma-separated list of keywords to exclude from the Installed Software sheet.")

    args = parser.parse_args()
    
    print(get_ascii_art())
    
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
            mode = config.get("mode")
            
            if mode in ["import", "i", "im", "import mode"]:
                args.import_mode = True
            elif mode in ["export", "e", "ex", "export mode"]:
                args.export_mode = True
            elif mode in ["convert", "c", "co", "convert mode"]:
                args.convert_mode = True
            
            # General settings
            args.nessus_url = config.get("nessus_url")
            args.api_token = config.get("api_token")
            args.username = config.get("username")
            args.password = config.get("password")
            args.secure = config.get("secure")
            args.verbose = config.get("verbose")
            args.threads = config.get("threads")
            
            # Import mode settings
            args.directory = config.get("directory")
            args.no_recursive = config.get("no_recursive")
            args.upload_folder = config.get("upload_folder")
            
            # Export mode settings
            args.csv = config.get("csv")
            args.excel = config.get("excel")
            
            # Convert mode settings
            args.csv_path = config.get("csv")
            args.output_excel = config.get("excel")
            args.software_exclusion_keywords = config.get("software_exclusion_keywords")
            
            if type(args.software_exclusion_keywords) == list:
                args.software_exclusion_keywords = ",".join(args.software_exclusion_keywords)

    if not args.import_mode and not args.export_mode and not args.convert_mode:
        while True:
            mode = get_non_blank_input("Would you like to import, export or convert a Nessus scan? (I/E/C): ", logger=logger).strip().lower()
            if mode in ["import", "i", "im", "import mode"]:
                args.import_mode = True
                break
            elif mode in ["export", "e", "ex", "export mode"]:
                args.export_mode = True
                break
            elif mode in ["convert", "c", "co", "convert mode"]:
                args.convert_mode = True
                break
            else:
                logger.error("Not a valid option. Please select either import, export or convert (I/E/C): ")
            
    if args.import_mode or args.export_mode:
        if not args.nessus_url:
            args.nessus_url = get_user_input_with_default("Enter the Nessus server URL (e.g. https://localhost:8834) [https://localhost:8834]: ", logger=logger, default="https://localhost:8834")
        if not (args.nessus_url.startswith("http://") or args.nessus_url.startswith("https://")):
            args.nessus_url = "https://" + args.nessus_url
        
    if args.import_mode and not args.directory:
        args.directory = get_user_input_with_default("Enter the directory containing .nessus files (e.g. /path/to/directory/with/nessus/files) [CURRENT DIRECTORY]: ", logger=logger, default=os.getcwd())
    if args.import_mode and not os.path.isdir(args.directory):
        logger.error(f"Error: Directory '{args.directory}' does not exist.")
        sys.exit(1)
        
    if args.export_mode and not args.csv:
        args.csv = get_user_input_with_default("What do you want to name the output CSV file? (e.g. output.csv) [output.csv]: ", logger=logger, default="output.csv")
        if not args.csv.lower().endswith('.csv'):
            args.csv += '.csv'
        
    if args.convert_mode and not args.csv_path:
        args.csv_path = get_non_blank_input("What is the filepath of the CSV file to convert to Excel (e.g. /path/to/file.csv): ", logger=logger)
        
    if args.convert_mode and not os.path.isfile(args.csv_path):
        logger.error(f"Error: File '{args.csv_path}' does not exist.")
        sys.exit(1)
        
    if args.convert_mode and not args.output_excel:
        args.output_excel = get_user_input_with_default("What do you want to name the output Excel file? (e.g. output.xlsx) [output.xlsx]: ", logger=logger, default="output.xlsx")
        if not args.output_excel.lower().endswith('.xlsx'):
            args.output_excel += '.xlsx'
        
    if args.convert_mode and args.software_exclusion_keywords:
        args.software_exclusion_keywords = args.software_exclusion_keywords.split(",")
        if args.software_exclusion_keywords == [""]:
            args.software_exclusion_keywords = None
        
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
        nessus_convert(args.csv_path, args.output_excel, logger, args.software_exclusion_keywords)
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

