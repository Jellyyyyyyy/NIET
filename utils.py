import getpass
import os
import re


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


def get_non_blank_input(prompt, password=False, validate=None,logger=None):
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
    if default:
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

