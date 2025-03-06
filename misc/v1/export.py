#!/usr/bin/env python3
import os
import sys
import time
import argparse
import requests
import logging
import concurrent.futures

from urllib3.exceptions import InsecureRequestWarning
import urllib3

from nessus_convert import csv_to_excel

# Disable SSL warnings for self-signed certificates if using --insecure.
urllib3.disable_warnings(InsecureRequestWarning)

class NessusAPI:
    """Simple wrapper to interact with the Nessus API."""
    def __init__(self, base_url, access_key, secret_key, verify=True, logger=None):
        self.base_url = base_url.rstrip('/')
        self.verify = verify
        self.logger = logger or logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json"
        })

    def check_connection(self):
        """Check if the Nessus server is reachable via the /server/status endpoint."""
        try:
            url = f"{self.base_url}/server/status"
            resp = self.session.get(url, verify=self.verify, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("Nessus server status: %s", data)
            return True
        except Exception as e:
            self.logger.error("Unable to connect to Nessus server at %s: %s", self.base_url, e)
            return False

    def get_folders(self):
        """
        Retrieve the list of folders from Nessus.
        Returns a dictionary mapping folder names to folder IDs.
        """
        try:
            url = f"{self.base_url}/folders"
            resp = self.session.get(url, verify=self.verify, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            folders = data.get("folders", [])
            self.logger.debug("Retrieved %d folders from Nessus", len(folders))
            return {folder["name"]: folder["id"] for folder in folders}
        except Exception as e:
            self.logger.error("Error retrieving folders: %s", e)
            return {}

    def get_scans(self):
        """
        Retrieve the list of scans from Nessus.
        Returns a list of scan dictionaries.
        """
        try:
            url = f"{self.base_url}/scans"
            resp = self.session.get(url, verify=self.verify, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            scans = data.get("scans", [])
            self.logger.debug("Retrieved %d scans from Nessus", len(scans))
            return scans
        except Exception as e:
            self.logger.error("Error retrieving scans: %s", e)
            return []

    def export_scan(self, scan_id):
        """
        Export a scan (in CSV format) and return its CSV content as a string.
        The process is asynchronous: first create an export request, poll until ready,
        and then download the file.
        """
        try:
            # Request export (using CSV format)
            payload = {"format": "csv"}
            url = f"{self.base_url}/scans/{scan_id}/export"
            self.logger.debug("Requesting export for scan ID %s", scan_id)
            resp = self.session.post(url, json=payload, verify=self.verify, timeout=10)
            resp.raise_for_status()
            file_id = resp.json().get("file")
            if not file_id:
                self.logger.error("No file id returned for scan %s export", scan_id)
                return None

            # Poll for export readiness.
            status_url = f"{self.base_url}/scans/{scan_id}/export/{file_id}/status"
            while True:
                status_resp = self.session.get(status_url, verify=self.verify, timeout=10)
                status_resp.raise_for_status()
                status = status_resp.json().get("status")
                self.logger.debug("Scan %s export status: %s", scan_id, status)
                if status == "ready":
                    break
                time.sleep(1)

            # Download the export.
            download_url = f"{self.base_url}/scans/{scan_id}/export/{file_id}/download"
            self.logger.debug("Downloading export for scan ID %s", scan_id)
            download_resp = self.session.get(download_url, verify=self.verify, timeout=30)
            download_resp.raise_for_status()
            return download_resp.text
        except Exception as e:
            self.logger.error("Error exporting scan %s: %s", scan_id, e)
            return None


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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Interactively export Nessus scans as CSV and merge them into one file."
    )
    parser.add_argument("--nessus-url", required=True,
                        help="Base URL of the Nessus API (e.g. https://localhost:8834)")
    parser.add_argument("--access-key", required=True,
                        help="Your Nessus API access key")
    parser.add_argument("--secret-key", required=True,
                        help="Your Nessus API secret key")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable SSL verification (for self-signed certificates)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose (debug) logging")
    parser.add_argument("--threads", type=int, default=1,
                        help="Number of threads to use for exporting scans (default: 1)")
    parser.add_argument("--csv", help="Directly specify the merged output CSV file. "
                                      "If the file exists, you'll be prompted to overwrite, append or cancel.")
    # New argument to specify Excel output file.
    parser.add_argument("--excel", help="Output Excel file name (with .xlsx extension) for converting the merged CSV file into an Excel workbook with separated Vulnerabilities and Compliance sheets.")
    return parser.parse_args()


def check_file_mode(filename, prompt_text="File '{}' already exists. Overwrite, append, or cancel? [O/A/C]: "):
    """Check if a file exists and ask the user to choose a mode."""
    if os.path.exists(filename):
        while True:
            choice = input(prompt_text.format(filename)).strip().lower()
            if choice in ('overwrite', 'o'):
                return "w"
            elif choice in ('append', 'a'):
                return "a"
            elif choice in ('cancel', 'c'):
                print("Operation cancelled.")
                sys.exit(0)
            else:
                print("Invalid choice. Please enter 'O' (overwrite), 'A' (append) or 'C' (cancel).")
    else:
        return "w"


def interactive_export(api, logger, preset_output_filename=None):
    """
    Interactively ask the user for scan selections and optionally the merged output filename.
    If preset_output_filename is provided, it will be used instead of prompting.
    
    Returns:
        merged_filename (str): The output CSV filename.
        selected_scans (dict): Mapping from scan id to a tuple (scan_name, folder_name).
    """
    if preset_output_filename:
        merged_filename = preset_output_filename.strip()
    else:
        merged_filename = input("Enter the name for the merged output CSV file: ").strip()
        if not merged_filename:
            logger.error("No merged output filename provided. Exiting.")
            sys.exit(1)

    selected_scans = {}  # key: scan id, value: (scan name, folder name)

    # First, try to get folders.
    folders = api.get_folders()
    if folders:
        # Folder selection mode.
        while True:
            folder_list = sorted(folders.items(), key=lambda x: x[0].lower())
            print("\nAvailable Folders:")
            for idx, (fname, _) in enumerate(folder_list, start=1):
                print(f"{idx}. {fname}")
            folder_choice = input("Select a folder (by number or name, or type 'exit' to finish selection): ").strip()
            if folder_choice.lower() == "exit":
                break

            selected_folder = None
            if folder_choice.isdigit():
                num = int(folder_choice)
                if 1 <= num <= len(folder_list):
                    selected_folder = folder_list[num - 1]
                else:
                    print("Invalid folder number.")
                    continue
            else:
                # Match folder by name (case-insensitive).
                matches = [item for item in folder_list if item[0].lower() == folder_choice.lower()]
                if matches:
                    selected_folder = matches[0]
                else:
                    print("Folder not found.")
                    continue

            folder_name, folder_id = selected_folder
            logger.info("Selected folder: %s (ID: %s)", folder_name, folder_id)

            # Retrieve scans and filter by the selected folder.
            scans = api.get_scans()
            folder_scans = [scan for scan in scans if scan.get("folder_id") == folder_id]
            if not folder_scans:
                print(f"No scans found in folder '{folder_name}'.")
                continue

            print(f"\nScans in folder '{folder_name}':")
            for idx, scan in enumerate(folder_scans, start=1):
                print(f"{idx}. {scan.get('name')} (ID: {scan.get('id')})")

            print("\nEnter the scan numbers to toggle selection using ranges or individual numbers.")
            print("Type 'all' to select all scans in this folder, or 'back' to return to the folder list.")
            while True:
                scan_choice = input("Your selection (e.g., '1-3,5,7'): ").strip()
                if scan_choice.lower() == "back":
                    break
                elif scan_choice.lower() == "all":
                    for scan in folder_scans:
                        selected_scans[scan.get("id")] = (scan.get("name"), folder_name)
                    print(f"All scans from folder '{folder_name}' selected.")
                    break
                else:
                    try:
                        indices = parse_range_input(scan_choice, len(folder_scans))
                    except ValueError as e:
                        print(f"Error: {e}. Please try again.")
                        continue
                    for idx in indices:
                        scan = folder_scans[idx - 1]  # list is 0-indexed, display is 1-indexed
                        scan_id = scan.get("id")
                        # Toggle selection: add if not selected, remove if already selected.
                        if scan_id in selected_scans:
                            del selected_scans[scan_id]
                            print(f"Removed scan: {scan.get('name')}")
                        else:
                            selected_scans[scan_id] = (scan.get("name"), folder_name)
                            print(f"Added scan: {scan.get('name')}")
                    further = input("Do you want to select anymore scans from this folder? (Y/N): ").strip().lower()
                    if further in ["no", "n"]:
                        break

            more = input("Do you want to select scans from another folder? (yes/no): ").strip().lower()
            if more not in ["yes", "y"]:
                break

    else:
        # No folders exist: list all scans directly.
        logger.info("No folders found on the Nessus server. Listing all scans directly.")
        scans = api.get_scans()
        if not scans:
            logger.error("No scans found on Nessus. Exiting.")
            sys.exit(1)
        while True:
            print("\nAvailable Scans:")
            for idx, scan in enumerate(scans, start=1):
                print(f"{idx}. {scan.get('name')} (ID: {scan.get('id')})")
            print("\nEnter the scan numbers to toggle selection using ranges or individual numbers.")
            print("Type 'all' to select all scans, or 'exit' to finish selection.")
            scan_choice = input("Your selection (e.g., '1-3,5'): ").strip()
            if scan_choice.lower() == "exit":
                break
            elif scan_choice.lower() == "all":
                for scan in scans:
                    selected_scans[scan.get("id")] = (scan.get("name"), "No Folder")
                print("All scans selected.")
                break
            else:
                try:
                    indices = parse_range_input(scan_choice, len(scans))
                except ValueError as e:
                    print(f"Error: {e}. Please try again.")
                    continue
                for idx in indices:
                    scan = scans[idx - 1]
                    scan_id = scan.get("id")
                    if scan_id in selected_scans:
                        del selected_scans[scan_id]
                        print(f"Removed scan: {scan.get('name')}")
                    else:
                        selected_scans[scan_id] = (scan.get("name"), "No Folder")
                        print(f"Added scan: {scan.get('name')}")
                further = input("Modify selection further? (type 'done' to finish): ").strip().lower()
                if further == "done":
                    break

    return merged_filename, selected_scans


def merge_csv_contents(csv_contents_list, output_filename, logger, mode="w"):
    """
    Merge multiple CSV content strings into a single CSV file.
    Only the header from the first CSV is retained.
    If mode is 'a' (append) and the file exists with content, the headers from the new exports are skipped.
    """
    try:
        # If appending and the file is empty, switch to write mode.
        if mode == "a" and os.path.exists(output_filename) and os.path.getsize(output_filename) == 0:
            mode = "w"

        if mode == "a":
            with open(output_filename, "a", newline="", encoding="utf-8") as fout:
                for content in csv_contents_list:
                    lines = content.splitlines()
                    if not lines:
                        continue
                    # Always skip header when appending.
                    for line in lines[1:]:
                        fout.write(line + "\n")
            logger.info("Appended CSV file at: %s", output_filename)
        else:
            with open(output_filename, "w", newline="", encoding="utf-8") as fout:
                for idx, content in enumerate(csv_contents_list):
                    lines = content.splitlines()
                    if not lines:
                        continue
                    if idx == 0:
                        # Write the entire first CSV including its header.
                        for line in lines:
                            fout.write(line + "\n")
                    else:
                        # Skip the header line in subsequent CSVs.
                        for line in lines[1:]:
                            fout.write(line + "\n")
            logger.info("Created merged CSV file at: %s", output_filename)
    except Exception as e:
        logger.error("Error merging CSV files: %s", e)


    

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

    logger.info("Starting Nessus export/merge process...")
    # Initialize Nessus API client.
    api = NessusAPI(
        base_url=args.nessus_url,
        access_key=args.access_key,
        secret_key=args.secret_key,
        verify=not args.insecure,
        logger=logger
    )

    if not api.check_connection():
        logger.error("Unable to connect to Nessus server. Exiting.")
        sys.exit(1)

    # Use the --csv flag if provided; otherwise, prompt for the output filename.
    if args.csv:
        merged_filename, selected_scans = interactive_export(api, logger, preset_output_filename=args.csv)
    else:
        merged_filename, selected_scans = interactive_export(api, logger)

    # Append '.csv' extension if missing.
    if not merged_filename.lower().endswith('.csv'):
        merged_filename += '.csv'

    # Check file existence and get desired file mode ("w" for overwrite, "a" for append).
    file_mode = check_file_mode(merged_filename)

    if not selected_scans:
        logger.error("No scans were selected. Exiting.")
        sys.exit(1)

    logger.info("Selected %d scan(s) for export.", len(selected_scans))
    
    # Export scans.
    csv_contents = {}  # key: scan_id, value: CSV content string
    if args.threads > 1:
        logger.info("Exporting scans using %d threads...", args.threads)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_scan = {
                executor.submit(api.export_scan, scan_id): scan_id
                for scan_id in selected_scans
            }
            for future in concurrent.futures.as_completed(future_to_scan):
                scan_id = future_to_scan[future]
                scan_name, folder_name = selected_scans[scan_id]
                try:
                    content = future.result()
                    if content:
                        csv_contents[scan_id] = content
                        logger.info("Scan '%s' exported successfully.", scan_name)
                    else:
                        logger.error("Failed to export scan '%s' (ID: %s).", scan_name, scan_id)
                except Exception as e:
                    logger.error("Error exporting scan '%s' (ID: %s): %s", scan_name, scan_id, e)
    else:
        logger.info("Exporting scans sequentially...")
        for scan_id, (scan_name, folder_name) in selected_scans.items():
            logger.info("Exporting scan '%s' (ID: %s) from folder '%s'...", scan_name, scan_id, folder_name)
            content = api.export_scan(scan_id)
            if content:
                csv_contents[scan_id] = content
                logger.info("Scan '%s' exported successfully.", scan_name)
            else:
                logger.error("Failed to export scan '%s' (ID: %s).", scan_name, scan_id)

    if not csv_contents:
        logger.error("No CSV exports were obtained. Exiting.")
        sys.exit(1)

    # Merge CSV contents in the order the scans were selected.
    ordered_scan_ids = list(selected_scans.keys())
    csv_contents_list = [csv_contents[scan_id] for scan_id in ordered_scan_ids if scan_id in csv_contents]

    merge_csv_contents(csv_contents_list, merged_filename, logger, mode=file_mode)
    logger.info("CSV merge process complete.")

    # If an Excel output filename is provided, convert the CSV to Excel.
    if args.excel:
        excel_filename = args.excel
        if not excel_filename.lower().endswith('.xlsx'):
            excel_filename += '.xlsx'
        csv_to_excel(merged_filename, excel_filename, logger)

if __name__ == '__main__':
    main()
