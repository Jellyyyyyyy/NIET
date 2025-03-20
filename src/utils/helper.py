import getpass
import os
import re
from lxml import etree
import pandas as pd


PREDEFINED_SUSAN_ITEMS_TO_REMOVE_XML = [
    {"label": "2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'", "strToFind": "2.2.2 (L1)"},
    {"label": "2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'", "strToFind": "2.2.3 (L1)"},
    {"label": "2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher", "strToFind": "2.3.9.5 (L1)"},
    {"label": "9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'", "strToFind": "9.2.1 (L1)"},
    {"label": "9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'", "strToFind": "9.2.2 (L1)"},
    {"label": "9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'", "strToFind": "9.2.3 (L1)"},
    {"label": "9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'", "strToFind": "9.3.1 (L1)"},
    {"label": "9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'", "strToFind": "9.3.2 (L1)"},
    {"label": "9.3.3 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'", "strToFind": "9.3.3 (L1)"},
    {"label": "5.25 (L2) Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'", "strToFind": "5.25 (L2)"},
    {"label": "18.10.42.17 (L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'", "strToFind": "18.10.42.17 (L1)"},
    {"label": "Symantec Antivirus Software Detection and Status", "strToFind": "Symantec Antivirus Software Detection and Status"}
]

PREDEFINED_SUSAN_ITEMS_TO_REMOVE_CSV = [
    {"label": "2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'", "strToFind": "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"},
    {"label": "2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'", "strToFind": "Ensure 'Act as part of the operating system' is set to 'No One'"},
    {"label": "2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher", "strToFind": "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"},
    {"label": "9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'", "strToFind": "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"},
    {"label": "9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'", "strToFind": "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"},
    {"label": "9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'", "strToFind": "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"},
    {"label": "9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'", "strToFind": "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"},
    {"label": "9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'", "strToFind": "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"},
    {"label": "9.3.3 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'", "strToFind": "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"},
    {"label": "5.25 (L2) Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'", "strToFind": "Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'"},
    {"label": "18.10.42.17 (L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'", "strToFind": "Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'"},
    {"label": "Symantec Antivirus Software Detection and Status", "strToFind": "Symantec Antivirus Software Detection and Status"}
]

def get_ascii_art():
    return r"""
NNNNNNNN        NNNNNNNN IIIIIIIIII EEEEEEEEEEEEEEEEEEEEEE TTTTTTTTTTTTTTTTTTTTTTT
N:::::::N       N::::::N I::::::::I E::::::::::::::::::::E T:::::::::::::::::::::T
N::::::::N      N::::::N I::::::::I E::::::::::::::::::::E T:::::::::::::::::::::T
N:::::::::N     N::::::N II::::::II EE::::::EEEEEEEEE::::E T:::::TT:::::::TT:::::T
N::::::::::N    N::::::N   I::::I     E:::::E       EEEEEE TTTTTT  T:::::T  TTTTTT
N:::::::::::N   N::::::N   I::::I     E:::::E                      T:::::T        
N:::::::N::::N  N::::::N   I::::I     E::::::EEEEEEEEEE            T:::::T        
N::::::N N::::N N::::::N   I::::I     E:::::::::::::::E            T:::::T        
N::::::N  N::::N:::::::N   I::::I     E:::::::::::::::E            T:::::T        
N::::::N   N:::::::::::N   I::::I     E::::::EEEEEEEEEE            T:::::T        
N::::::N    N::::::::::N   I::::I     E:::::E                      T:::::T        
N::::::N     N:::::::::N   I::::I     E:::::E       EEEEEE         T:::::T        
N::::::N      N::::::::N II::::::II EE::::::EEEEEEEE:::::E       TT:::::::TT      
N::::::N       N:::::::N I::::::::I E::::::::::::::::::::E       T:::::::::T      
N::::::N        N::::::N I::::::::I E::::::::::::::::::::E       T:::::::::T      
NNNNNNNN         NNNNNNN IIIIIIIIII EEEEEEEEEEEEEEEEEEEEEE       TTTTTTTTTTT      

"""


def get_authors():
    return "Made by Jellyyyyyyy & SimYanZhe"


def get_all_text(element):
    return ''.join(element.itertext())


def get_non_blank_input(prompt, password=False, validate=None, logger=None):
    """Prompt the user until a non-blank input is provided."""
    while True:
        value = getpass.getpass(prompt).strip() if password else input(prompt).strip()
        if value:
            if validate:
                if re.fullmatch(validate, value):
                    return value
                else:
                    if logger:
                        logger.error(f"Invalid input. Please try again.")
                    else:
                        print(f"Invalid input. Please try again.")
            else:
                return value
        if logger:
            logger.error("Input cannot be blank. Please try again.")
        else:
            print("Input cannot be blank. Please try again.")
            
            
def get_user_input_with_default(prompt, default, validate=None, logger=None):
    """Prompt the user for input, with a default value if the user just hits enter."""
    value = input(prompt).strip()
    if value:
        if validate:
            if re.fullmatch(validate, value):
                return value
            else:
                if logger:
                    logger.error(f"Invalid input. Please try again.")
                else:
                    print(f"Invalid input. Please try again.")
        else:
            return value
    else:
        if logger:
            logger.debug(f"Using default value: {default}")
        else:
            print(f"Using default value: {default}")
        return default
        

def get_user_confirmation(prompt, default=None):
    """Prompt the user until a yes/no input is provided."""
    while True:
        value = input(prompt).strip().lower()
        if value in ["y", "ye", "yes"] or (default is True and value == ""):
            return True
        if value in ["n", "no"] or (default is False and value == ""):
            return False
        
        
def check_min_nessus_files(directory, min_files=1, file_extension=".nessus", recursive=True):
    """Check if there are any .nessus files in the directory."""
    nessus_files = []
    if recursive:
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                if filename.lower().endswith(file_extension):
                    nessus_files.append(os.path.abspath(os.path.join(dirpath, filename)))
    else:
        for filename in os.listdir(directory):
            if filename.lower().endswith(file_extension):
                nessus_files.append(os.path.abspath(os.path.join(directory, filename)))
    if len(nessus_files) >= min_files:
        return True
    return False
        
        
def gather_nessus_files(root_dir, recursive=True):
    """Return a list of absolute paths for all .nessus files in the directory.
       If recursive is False, only files in the root directory are returned."""
    nessus_files = []
    if recursive:
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if filename.lower().endswith('.nessus'):
                    nessus_files.append(os.path.abspath(os.path.join(dirpath, filename)))
    else:
        for filename in os.listdir(root_dir):
            full_path = os.path.join(root_dir, filename)
            if os.path.isfile(full_path) and filename.lower().endswith('.nessus'):
                nessus_files.append(os.path.abspath(full_path))
    return nessus_files
          
          
def parse_range_input(input_str, max_val):
    """
    Parse a string like "1-5,7,10-12" (or with spaces) and return a set of integers.
    Raises ValueError if input is invalid or out-of-range.
    """
    result = set()
    # Replace commas with spaces and split on whitespace.
    tokens = input_str.replace(',', ' ').split()
    for token in tokens:
        if '-' in token:
            parts = token.split('-')
            if len(parts) != 2:
                raise ValueError(f"Invalid range format: '{token}'")
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid number in range: '{token}'")
            if start > end:
                raise ValueError(f"Range '{token}' is invalid (start greater than end).")
            if start < 1 or end > max_val:
                raise ValueError(f"Range '{token}' is out of valid bounds (1-{max_val}).")
            result.update(range(start, end + 1))
        else:
            try:
                num = int(token)
            except ValueError:
                raise ValueError(f"Invalid number: '{token}'")
            if num < 1 or num > max_val:
                raise ValueError(f"Number '{num}' is out of valid bounds (1-{max_val}).")
            result.add(num)
    return result


def try_parse_with_encodings(file_path, encodings=None, logger=None):
    if encodings is None:
        encodings = ['utf-8', 'cp1252', 'latin-1']
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as file:
                tree = etree.parse(file)
                if logger:
                    logger.debug(f"Successfully parsed XML file {file_path} with encoding: {encoding}")
                else:
                    print(f"Successfully parsed XML file {file_path} with encoding: {encoding}")
                return tree
        except Exception as e:
            if logger:
                logger.error(f"Failed to parse with encoding '{encoding}': {e}")
            else:
                print(f"Failed to parse with encoding '{encoding}': {e}")
    raise ValueError(f"Unable to parse the XML file {file_path} with the provided encodings.")


def check_for_susan_items_xml(file_path, susan_items=None, logger=None):
    tree = try_parse_with_encodings(file_path, logger=logger)
    root = tree.getroot()
    
    if susan_items is None:
        susan_items = [item['strToFind'] for item in PREDEFINED_SUSAN_ITEMS_TO_REMOVE_XML]
        
    found_items = []
        
    for strToFind in susan_items:
        if strToFind in get_all_text(root):
            found_items.append(strToFind)
    return found_items


def check_for_susan_items_csv(file_path, column_name, susan_items=None):
    df = pd.read_csv(file_path)
    
    if susan_items is None:
        susan_items = [item['strToFind'] for item in PREDEFINED_SUSAN_ITEMS_TO_REMOVE_CSV]
    
    if column_name is None:
        column_name = "Description"
    
    found_items = []
    for strToFind in susan_items:
        # Filter rows where column contains the text
        print(strToFind)
        matches = df[column_name].astype(str).str.contains(re.escape(strToFind), case=False, na=False, regex=True)

        # Check if any matches are found
        if matches.any():
            found_items.append(strToFind)
    
    return found_items


def get_susan_items_to_remove(file_type="XML", logger=None):
    """
    Prompt the user to choose items to remove from the XML file.
    Returns a list of items to remove.
    """
    if file_type.lower() == "xml":
        susan_items = PREDEFINED_SUSAN_ITEMS_TO_REMOVE_XML
    elif file_type.lower() == "csv":
        susan_items = PREDEFINED_SUSAN_ITEMS_TO_REMOVE_CSV
        
    print("\nChoose the Susan items to remove if found in file:\n")
    for index, item in enumerate(susan_items):
        print(f"{index + 1}. {item['label']}")
    susan_choice  = get_user_input_with_default("\nYour selection (e.g., '1-3,5,7') [All]: ", logger=logger, default="all").strip()
    if susan_choice.lower() == "all":
        return [item['strToFind'] for item in susan_items]
    else:
        try:
            indices = parse_range_input(susan_choice, len(susan_items))
            return [susan_items[index - 1]['strToFind'] for index in indices]
        except ValueError as e:
            logger.error(f"Error: {e}. Please try again.")
            return None


def remove_report_items_from_xml(file_path, target_texts, logger=None):
    tree = try_parse_with_encodings(file_path, logger=logger)
    root = tree.getroot()
    count_dict = {}

    # Iterate through each ReportItem element in the XML
    for report_item in root.xpath("//ReportItem"):
        item_str = etree.tostring(report_item, pretty_print=True).decode("utf-8")
        for text in target_texts:
            if text in item_str:
                count_dict[text] = count_dict.get(text, 0) + 1
                parent = report_item.getparent()
                parent.remove(report_item)
                break

    if logger:
        logger.info(f"Removed ReportItems counts: {count_dict}")
    else:
        print(f"Removed ReportItems counts: {count_dict}")
    modified_xml = etree.tostring(root, pretty_print=True, encoding="UTF-8", xml_declaration=True)
    with open(file_path, "wb") as f:
        f.write(modified_xml)
    if logger:
        logger.info(f"Modified XML written to {file_path}")
    else:
        print(f"Modified XML written to {file_path}")
    return modified_xml


def remove_csv_rows_with_text(csv_file, column_name=None, susan_items=None, logger=None):
    df = pd.read_csv(csv_file)
    if column_name not in df.columns:
        if logger:
            logger.error(f"Column '{column_name}' not found in CSV file.")
        else:
            print(f"Column '{column_name}' not found in CSV file.")
        raise ValueError(f"Column '{column_name}' not found in CSV file.")
    
    if susan_items is None:
        susan_items = [item['strToFind'] for item in PREDEFINED_SUSAN_ITEMS_TO_REMOVE_CSV]
    if column_name is None:
        column_name = "Description"

    # Remove rows where the specified column contains the text (using substring search)
    for item in susan_items:
        df = df[~df[column_name].astype(str).str.contains(re.escape(item), case=False, na=False, regex=True)]

    # Save the filtered DataFrame
    df.to_csv(csv_file, index=False)

    # Logging or print confirmation
    if logger:
        logger.info(f"Filtered CSV written to {csv_file}")
    else:
        print(f"Filtered CSV written to {csv_file}")

    return df