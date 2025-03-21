import os
import sys
import re
import concurrent.futures
import threading
from utils.helper import check_for_susan_items_xml, get_susan_items_to_remove, get_non_blank_input, get_user_confirmation, gather_nessus_files, remove_report_items_from_xml


def choose_folder_interactively(nessus_api, folders):
    """
    Display available folders and prompt the user to enter a folder name or number.
    - If the user enters a number, the folder corresponding to that index is used.
    - If the user enters a name:
        - If it exists, that folder is used.
        - Otherwise, the user is asked whether to create the folder.
    Only allowed characters for a folder name are alphabets, numbers, dashes, spaces, and underscores.
    """
    print_folders = True
    while True:
        if folders:
            if print_folders:
                folder_list = sorted(folders.items(), key=lambda x: x[0].lower())
                print("Available Folders:")
                for idx, (fname, _) in enumerate(folder_list, start=1):
                    print(f"  {idx}. {fname}")
            folder_input = get_non_blank_input("Enter the folder name or number to use (Enter a new name to create the folder): ", logger=nessus_api.get_logger())
        else:
            nessus_api.get_logger().error("No folders found on the Nessus server.")
            folder_input = get_non_blank_input("Enter a new folder name to create: ", logger=nessus_api.get_logger())
        
        print_folders = True

        # If there are folders and input is a number, select from the list.
        if folder_input.isdigit() and folders:
            idx = int(folder_input)
            if 1 <= idx <= len(folder_list):
                selected = folder_list[idx - 1]
                nessus_api.get_logger().info(f"Using existing folder '{selected[0]}' (ID: {selected[1]}).")
                return selected[1]
            else:
                if get_user_confirmation(f"Could not find folder number {folder_input}. Do you want to create the folder named {folder_input}? (y/N): ", default=False):
                    folder_id = nessus_api.create_folder(folder_input)
                    if not folder_id:
                        sys.exit(1)
                    return folder_id

        else:
            if not re.match(r'^[A-Za-z0-9\s_-]+$', folder_input):
                nessus_api.get_logger().error("Invalid folder name. Only alphabets, numbers, dashes, spaces, and underscores are allowed.")
                print_folders = False
                continue
            
            if len(folder_input) > 20:
                nessus_api.get_logger().error("Max 20 characters allowed for folder name.")
                print_folders = False
                continue
            
            if folder_input in folders:
                nessus_api.get_logger().info(f"Using existing folder '{folder_input}' (ID: {folders[folder_input]}).")
                return folders[folder_input]
            else:
                if get_user_confirmation(f"Folder '{folder_input}' not found. Create new folder? (y/N): ", default=False):
                    folder_id = nessus_api.create_folder(folder_input)
                    if folder_id:
                        return folder_id
                    else:
                        nessus_api.get_logger().error("Failed to create folder")
                        sys.exit(1)


def process_file(folder_id, file_path, nessus_api, verbose=False, index=None, total=None):
    """
    For a given .nessus file, first upload it via /file/upload, then import it via /scans/import.
    Returns True if both steps succeed; otherwise False.
    If verbose is True, progress messages including file index are output.
    """
    if verbose and index and total:
        nessus_api.get_logger().debug(f"{'[' + f'{index}/{total}' + '] ' if index and total else ''} Uploading file: {file_path}")

    # Step 1: Upload the file.
    upload_response = nessus_api.upload_file(file_path, index, total)
    
    # Step 2: Import the scan.
    import_response = nessus_api.import_scan(folder_id, file_path, upload_response, index, total)

    return import_response


def nessus_import(nessus_api, directory=None, filepaths=None, flags=None):
    """
    Import .nessus files into Nessus.

    Args:
        nessus_api (NessusAPI): The Nessus API object.
        logger (logging.Logger): The logger object.
        directory (str): The directory containing the .nessus files to import.
        flags (argparse.Namespace): The command line arguments.

    Returns:
        None
    """
    # Determine the folder to upload to.
    if flags is None:
        flags = {}
    
    folders = nessus_api.get_folders()
    if flags.upload_folder:
        if flags.upload_folder in folders:
            folder_id = folders[flags.upload_folder]
            nessus_api.get_logger().info(f"Using specified folder '{flags.upload_folder}' (ID: {folder_id}).")
        else:
            nessus_api.get_logger().error(f"Specified folder '{flags.upload_folder}' not found on the Nessus server")
            
            if get_user_confirmation(f"Folder '{flags.upload_folder}' not found. Create new folder? (y/N): ", default=False):
                folder_id = nessus_api.create_folder(flags.upload_folder)
                if not folder_id:
                    sys.exit(1)
            else:
                nessus_api.get_logger().error(f"Folder '{flags.upload_folder}' not found and user did not want to create it.")
                sys.exit(1)
    else:
        folder_id = choose_folder_interactively(nessus_api, folders)

    # Gather .nessus files from the specified directory.
    nessus_files = []
    if directory:
        nessus_files.extend(gather_nessus_files(directory, recursive=flags.no_recursive))
    if filepaths:
        for filepath in filepaths:
            if os.path.isfile(filepath) and filepath.endswith('.nessus'):
                nessus_files.append(filepath)
            else:
                nessus_api.get_logger().error(f"File '{filepath}' is not a valid .nessus file.")
                
    total_files = len(nessus_files)
    nessus_api.get_logger().info(f"Found {total_files} .nessus file{'' if total_files == 1 else 's'}.")
    if total_files == 0:
        nessus_api.get_logger().info(f"No .nessus files found in directory {directory}")
        sys.exit(1)
    
    found = False
    for file in nessus_files:
        if check_for_susan_items_xml(file, flags.susan_items_to_remove or None, logger=nessus_api.get_logger()):
            nessus_api.get_logger().debug(f"Susan items found in {file}.")
            found = True
            
    if found and not flags.remove_susan and get_user_confirmation(f"Susan items found. Do you want to remove them? This will edit the Nessus file directly. (Y/n): ", default=True):
        flags.remove_susan = True
        
    if flags.remove_susan:
        if flags.susan_all_files:
            for file in nessus_files:
                items_to_remove = flags.susan_items_to_remove or get_susan_items_to_remove(file_type="XML", logger=nessus_api.get_logger())
                if items_to_remove:
                    nessus_api.get_logger().debug(f"Removing Susan items {items_to_remove} from {file}...")
                    remove_report_items_from_xml(file, items_to_remove, nessus_api.get_logger())
        else:
            items_to_remove = flags.susan_items_to_remove or get_susan_items_to_remove(file_type="XML", logger=nessus_api.get_logger())
            if items_to_remove:
                for file in nessus_files:
                    nessus_api.get_logger().debug(f"Removing Susan items {items_to_remove} from {file}...")
                    remove_report_items_from_xml(file, items_to_remove, nessus_api.get_logger())

    # Set up progress tracking.
    progress_lock = threading.Lock()
    progress_count = 0

    # Mapping of file paths to their (1-indexed) order for verbose progress.
    file_to_index = {f: i for i, f in enumerate(nessus_files, start=1)}

    success_count = 0
    failure_count = 0

    def process_wrapper(file_path):
        nonlocal progress_count
        index = file_to_index[file_path]
        result = process_file(folder_id, file_path, nessus_api, verbose=flags.verbose, index=index, total=total_files)
        with progress_lock:
            progress_count += 1
            if not flags.verbose:
                print(f"Progress: [{progress_count}/{total_files}]", end="\r", flush=True)
        return result

    if flags.threads > 1:
        nessus_api.get_logger().info(f"Processing files using {flags.threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=flags.threads) as executor:
            futures = {executor.submit(process_wrapper, file): file for file in nessus_files}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    success_count += 1
                else:
                    failure_count += 1
    else:
        nessus_api.get_logger().info("Processing files sequentially...")
        for file in nessus_files:
            result = process_wrapper(file)
            if result:
                success_count += 1
            else:
                failure_count += 1

    # Move to a new line after progress is complete.
    if not flags.verbose:
        print()

    nessus_api.get_logger().info(f"Import process complete: {success_count} succeeded, {failure_count} failed.")
