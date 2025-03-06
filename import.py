#!/usr/bin/env python3
"""
Interactive Nessus Import Script

This script uploads .nessus files found in a specified directory (with optional non‐recursive search)
to a Nessus server. It performs login using a username/password to retrieve a session token,
requires an API token, and then:
  1. Uploads each file via /file/upload.
  2. Imports the scan via /scans/import (using the returned filename).

If the user did not specify an upload folder via --upload-folder, the script will prompt
to choose (or create) a folder by entering its name or the corresponding number.
Files are processed concurrently if the --threads flag is greater than 1.
"""

import os
import sys
import re
import argparse
import logging
import getpass
import concurrent.futures
import threading
import requests

from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable SSL warnings for self-signed certificates.
urllib3.disable_warnings(InsecureRequestWarning)


def get_non_blank_input(prompt):
    """Prompt the user until a non-blank input is provided."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        else:
            print("Input cannot be blank. Please enter a value.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Interactive Nessus import script: Upload .nessus files and import scans."
    )
    parser.add_argument("-d", "--directory",
                        help="Directory containing .nessus files to import.")
    parser.add_argument("-N", "--no-recursive", action="store_true",
                        help="Do not recursively search for .nessus files.")
    parser.add_argument("-u", "--nessus-url",
                        help="Base URL of the Nessus server (e.g. https://localhost:8834)")
    parser.add_argument("-a", "--api-token",
                        help="API token to use (if not specified, you will be prompted).")
    parser.add_argument("-F", "--upload-folder", default=None,
                        help="Name of the folder to upload scans into. If not provided, you'll be prompted.")
    parser.add_argument("-S", "--secure", type=bool, default=False,
                        help="Enables SSL verification (default: False).")
    parser.add_argument("-T", "--threads", type=int, default=1,
                        help="Number of threads to use for importing files (default: 1).")
    parser.add_argument("-V", "--verbose", action="store_true",
                        help="Enable verbose output.")
    args = parser.parse_args()

    # Prompt for missing required values (with non-blank checking).
    if not args.directory:
        args.directory = get_non_blank_input("Enter the directory containing .nessus files: ")
    if not os.path.isdir(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist.")
        sys.exit(1)

    if not args.nessus_url:
        args.nessus_url = get_non_blank_input("Enter the Nessus server URL: ")
    # Auto-append https:// if scheme is missing.
    if not (args.nessus_url.startswith("http://") or args.nessus_url.startswith("https://")):
        args.nessus_url = "https://" + args.nessus_url

    if not args.api_token:
        args.api_token = get_non_blank_input("Enter your Nessus API token: ")

    return args


def login_nessus(nessus_url, username, password, verify=True):
    """Log in to Nessus and return the session token."""
    login_url = f"{nessus_url.rstrip('/')}/session"
    payload = {"username": username, "password": password}
    response = requests.post(login_url, json=payload, verify=verify, timeout=10)
    response.raise_for_status()
    data = response.json()
    token = data.get("token")
    if not token:
        raise Exception("Token not found in login response.")
    return token


def get_folders(session, nessus_url, verify=True, logger=None):
    """Retrieve folder list from Nessus. Returns a dict mapping folder names to folder IDs."""
    try:
        url = f"{nessus_url.rstrip('/')}/folders"
        response = session.get(url, verify=verify, timeout=10)
        response.raise_for_status()
        data = response.json()
        folders = data.get("folders", [])
        if logger:
            logger.debug("Retrieved %d folders from Nessus", len(folders))
        return {folder["name"]: folder["id"] for folder in folders}
    except Exception as e:
        if logger:
            logger.error("Error retrieving folders: %s", e)
        return {}


def create_folder(session, nessus_url, folder_name, verify=True, logger=None):
    """
    Create a new folder on the Nessus server.
    Returns the new folder's ID or None if creation fails.
    """
    url = f"{nessus_url.rstrip('/')}/folders"
    payload = {"name": folder_name}
    try:
        response = session.post(url, json=payload, verify=verify, timeout=10)
        response.raise_for_status()
        data = response.json()
        folder_id = data.get("id")
        if not folder_id:
            if logger:
                logger.error("Folder creation failed for '%s'; no ID returned.", folder_name)
            return None
        if logger:
            logger.info("Created folder '%s' with ID %s", folder_name, folder_id)
        return folder_id
    except Exception as e:
        if logger:
            logger.error("Error creating folder '%s': %s", folder_name, e)
        return None


def choose_folder_interactively(folders, session, nessus_url, verify, logger):
    """
    Display available folders and prompt the user to enter a folder name or number.
    - If the user enters a number, the folder corresponding to that index is used.
    - If the user enters a name:
        - If it exists, that folder is used.
        - Otherwise, the user is asked whether to create the folder.
    Only allowed characters for a folder name are alphabets, numbers, dashes, spaces, and underscores.
    """
    while True:
        if folders:
            folder_list = sorted(folders.items(), key=lambda x: x[0].lower())
            print("Available Folders:")
            for idx, (fname, _) in enumerate(folder_list, start=1):
                print(f"  {idx}. {fname}")
        else:
            print("No folders found on the Nessus server.")

        folder_input = get_non_blank_input("Enter the folder name or number to use (Enter a new name to create the folder): ")

        # If input is a number, assume selection from the list.
        if folder_input.isdigit():
            idx = int(folder_input)
            if folders:
                if 1 <= idx <= len(folder_list):
                    selected = folder_list[idx - 1]
                    logger.info("Using existing folder '%s' (ID: %s).", selected[0], selected[1])
                    return selected[1]
                else:
                    print("Invalid folder number. Please try again.")
                    continue
            else:
                print("No folders available to select by number. Please enter a folder name.")
                continue
        else:
            # Validate folder name.
            if not re.match(r'^[A-Za-z0-9\s_-]+$', folder_input):
                print("Invalid folder name. Only alphabets, numbers, dashes, spaces, and underscores are allowed.")
                continue
            if folder_input in folders:
                logger.info("Using existing folder '%s' (ID: %s).", folder_input, folders[folder_input])
                return folders[folder_input]
            else:
                yn = input(f"Folder '{folder_input}' not found. Create new folder? (Y/N): ").strip().lower()
                if yn.startswith("y"):
                    folder_id = create_folder(session, nessus_url, folder_input, verify=verify, logger=logger)
                    if folder_id:
                        return folder_id
                    else:
                        print("Failed to create folder. Please try again.")
                else:
                    print("Please try again.")


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


def process_file(file_path, nessus_url, folder_id, session, verify, logger, verbose=False, index=None, total=None):
    """
    For a given .nessus file, first upload it via /file/upload, then import it via /scans/import.
    Returns True if both steps succeed; otherwise False.
    If verbose is True, progress messages including file index are output.
    """
    if verbose and index and total:
        logger.debug("[%d/%d] Uploading file: %s", index, total, file_path)

    # Step 1: Upload the file.
    upload_url = f"{nessus_url.rstrip('/')}/file/upload"
    try:
        with open(file_path, 'rb') as f:
            files_dict = {"Filedata": f}
            response = session.post(upload_url, files=files_dict, verify=verify, timeout=30)
        response.raise_for_status()
        data = response.json()
        uploaded_file = data.get("fileuploaded")
        if not uploaded_file:
            logger.error("File upload failed for %s; no 'fileuploaded' returned.", file_path)
            return False
        if verbose and index and total:
            logger.debug("[%d/%d] Uploaded successfully as %s", index, total, uploaded_file)
    except Exception as e:
        logger.error("Error uploading file %s: %s", file_path, e)
        return False

    # Step 2: Import the scan.
    import_url = f"{nessus_url.rstrip('/')}/scans/import"
    payload = {"folder_id": folder_id, "file": uploaded_file}
    try:
        response = session.post(import_url, json=payload, verify=verify, timeout=30)
        response.raise_for_status()
        if verbose and index and total:
            logger.debug("[%d/%d] Imported scan from file: %s", index, total, file_path)
        return True
    except Exception as e:
        logger.error("Error importing scan for file %s: %s", file_path, e)
        return False


def main():
    args = parse_args()

    # Set up logging.
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=logging_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    logger = logging.getLogger(__name__)

    # Prepare Nessus URL.
    nessus_url = args.nessus_url.rstrip('/')

    # Allow up to 3 login attempts.
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        username = get_non_blank_input("Enter your Nessus username: ")
        while True:
            password = getpass.getpass("Enter your Nessus password: ").strip()
            if password:
                break
            print("Password cannot be blank.")
        try:
            token = login_nessus(nessus_url, username, password, verify=args.secure)
            logger.info("Login successful.")
            break
        except Exception as e:
            logger.error("Login attempt %d failed: %s", attempt, e)
            if attempt == max_attempts:
                print(f"Login failed after {max_attempts} attempts.")
                sys.exit(1)
            else:
                print(f"Login attempt {attempt}/{max_attempts} failed. Please try again.")

    # Create a session with the appropriate headers.
    session = requests.Session()
    session.headers.update({
        "X-Cookie": f"token={token}",
        "X-Api-Token": args.api_token
    })

    # Determine the folder to upload to.
    folders = get_folders(session, nessus_url, verify=args.secure, logger=logger)
    if args.upload_folder:
        if args.upload_folder in folders:
            folder_id = folders[args.upload_folder]
            logger.info("Using specified folder '%s' (ID: %s).", args.upload_folder, folder_id)
        else:
            print(f"Specified folder '{args.upload_folder}' not found on the Nessus server.")
            # Automatically attempt to create the folder.
            folder_id = create_folder(session, nessus_url, args.upload_folder, verify=args.secure, logger=logger)
            if not folder_id:
                # Fall back to interactive folder selection/creation.
                folder_id = choose_folder_interactively(folders, session, nessus_url, verify=args.secure, logger=logger)
    else:
        folder_id = choose_folder_interactively(folders, session, nessus_url, verify=args.secure, logger=logger)

    # Gather .nessus files from the specified directory.
    recursive = not args.no_recursive
    nessus_files = gather_nessus_files(args.directory, recursive=recursive)
    total_files = len(nessus_files)
    logger.info("Found %d .nessus file%s.", total_files, "" if total_files == 1 else "s")
    if total_files == 0:
        sys.exit(0)

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
        result = process_file(
            file_path, nessus_url, folder_id, session,
            verify=args.secure, logger=logger,
            verbose=args.verbose, index=index, total=total_files
        )
        with progress_lock:
            progress_count += 1
            if not args.verbose:
                print(f"Progress: [{progress_count}/{total_files}]", end="\r", flush=True)
        return file_path, result

    if args.threads > 1:
        logger.info("Processing files using %d threads...", args.threads)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(process_wrapper, file): file for file in nessus_files}
            for future in concurrent.futures.as_completed(futures):
                file_path, result = future.result()
                if result:
                    success_count += 1
                else:
                    failure_count += 1
    else:
        logger.info("Processing files sequentially...")
        for file in nessus_files:
            _, result = process_wrapper(file)
            if result:
                success_count += 1
            else:
                failure_count += 1

    # Move to a new line after progress is complete.
    if not args.verbose:
        print()

    logger.info("Import process complete: %d succeeded, %d failed.", success_count, failure_count)


if __name__ == '__main__':
    main()
