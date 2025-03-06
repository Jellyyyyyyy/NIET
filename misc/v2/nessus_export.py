#!/usr/bin/env python3
import os
import sys
import concurrent.futures
from utils import get_non_blank_input, get_user_confirmation, get_user_input_with_default, parse_range_input
from nessus_convert import nessus_convert


def check_file_mode(nessus_api, filename, prompt_text="File '{}' already exists. Overwrite (O), append (A), enter new name (N), or cancel (C)?: "):
    """Check if a file exists and ask the user to choose a mode."""
    while os.path.exists(filename):
        choice = get_non_blank_input(prompt_text.format(filename), logger=nessus_api.get_logger()).strip().lower()
        if choice in ('overwrite', 'o'):
            return "w", filename
        elif choice in ('append', 'a'):
            return "a", filename
        elif choice in ('new', 'n'):
            filename = get_user_input_with_default("Enter new file name (e.g. output.csv) [output.csv]: ", logger=nessus_api.get_logger(), default="output.csv").strip()
        elif choice in ('cancel', 'c'):
            nessus_api.get_logger().info("Operation cancelled.")
            sys.exit(0)
        else:
            nessus_api.get_logger().error("Invalid choice. Please enter 'O' (overwrite), 'A' (append), 'N' (new name), or 'C' (cancel).")
    
    return "w", filename


def select_folder(nessus_api, folders):
    """
    Interactively ask the user for a folder selection.
    Returns:
        folder_name (str): The selected folder name.
        folder_id (str): The selected folder ID.
        None if the user wants to exit.
    """
    while True:
        folder_choice = input("Select a folder (by number or name, or type 'exit' to finish selection): ").strip()
        if folder_choice.lower() == "exit":
            return None

        if folder_choice.isdigit():
            num = int(folder_choice)
            if 1 <= num <= len(folders):
                return folders[num - 1]
            else:
                nessus_api.get_logger().error("Invalid folder number.")
        else:
            matches = [item for item in folders if item[0].lower() == folder_choice.lower()]
            if matches:
                return matches[0]
            else:
                nessus_api.get_logger().error("Folder not found.")


def select_scans(nessus_api, scans, folder_name):
    """
    Interactively ask the user for scan selections.
    Returns:
        selected_scans (dict): Mapping from scan id to a tuple (scan_name, folder_name).
    """
    # Retrieve scans and filter by the selected folder.    
    print(f"\nScans in folder '{folder_name}':")
    for idx, scan in enumerate(scans, start=1):
        print(f"{idx}. {scan.get('name')} (ID: {scan.get('id')})")

    print("\nEnter the scan numbers to toggle selection using ranges or individual numbers.")
    print("Type 'all' to select all scans in this folder, or 'back' to return to the folder list.")
    
    selected_scans = {}
    while True:
        scan_choice = get_user_input_with_default("Your selection (e.g., '1-3,5,7') [All]: ", logger=nessus_api.get_logger(), default="all").strip()
        if scan_choice.lower() == "back":
            break
        elif scan_choice.lower() == "all":
            for scan in scans:
                selected_scans[scan.get("id")] = (scan.get("name"), folder_name)
            nessus_api.get_logger().info(f"All scans from folder '{folder_name}' selected.")
            break
        else:
            try:
                indices = parse_range_input(scan_choice, len(scans))
            except ValueError as e:
                nessus_api.get_logger().error(f"Error: {e}. Please try again.")
                continue
            for idx in indices:
                scan = scans[idx - 1]  # list is 0-indexed, display is 1-indexed
                scan_id = scan.get("id")
                # Toggle selection: add if not selected, remove if already selected.
                if scan_id in selected_scans:
                    del selected_scans[scan_id]
                    nessus_api.get_logger().info(f"Removed scan: {scan.get('name')}")
                else:
                    selected_scans[scan_id] = (scan.get("name"), folder_name)
                    nessus_api.get_logger().info(f"Added scan: {scan.get('name')}")
            if not get_user_confirmation("Do you want to select more scans from this folder? (y/N): ", default=False):
                break
            
    return selected_scans


def get_scans_to_export(nessus_api):
    """
    Interactively ask the user for scan selections
    
    Returns:
        selected_scans (dict): Mapping from scan id to a tuple (scan_name, folder_name).
    """
    selected_scans = {}  # key: scan id, value: (scan name, folder name)

    # First, try to get folders.
    folders = nessus_api.get_folders()
    if folders:
        # Folder selection mode.
        while True:
            folder_list = sorted(folders.items(), key=lambda x: x[0].lower())
            print("\nAvailable Folders:")
            for idx, (fname, _) in enumerate(folder_list, start=1):
                print(f"{idx}. {fname}")

            # Get user to select a folder.
            selected_folder = select_folder(nessus_api,folder_list)
            if selected_folder is None:
                break

            folder_name, folder_id = selected_folder
            nessus_api.get_logger().info(f"Selected folder: {folder_name} (ID: {folder_id})")

            # Get all scans in the selected folder, filter and get user to select scans.
            all_scans = nessus_api.get_scans()
            filtered_scans = [scan for scan in all_scans if scan.get("folder_id") == folder_id]
            if len(filtered_scans) == 0:
                nessus_api.get_logger().error(f"No scans found in folder '{folder_name}'.")
                continue
            
            selected_scans = select_scans(nessus_api, filtered_scans, folder_name)

            if not get_user_confirmation("Do you want to select scans from another folder? (y/N): ", default=False):    
                break

    return selected_scans


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
            logger.info(f"Appended CSV file at: {output_filename}")
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
            logger.info(f"Created merged CSV file at: {output_filename}")
    except Exception as e:
        logger.error(f"Error merging CSV files: {e}")
    

def nessus_export(nessus_api, csv_file, flags={}):
    # Use the --csv flag if provided; otherwise, prompt for the output filename.
    if csv_file:
        merged_filename = csv_file.strip()
    else:
        merged_filename = get_user_input_with_default("Enter the filename for the merged output CSV (e.g. output.csv) [output.csv]: ", logger=nessus_api.get_logger(), default="output.csv")
            
    # Append '.csv' extension if missing.
    if not merged_filename.lower().endswith('.csv'):
        merged_filename += '.csv'

    # Check file existence and get desired file mode ("w" for overwrite, "a" for append).
    file_mode, file_name_to_export_to = check_file_mode(nessus_api, merged_filename)
    
    # Get scans to export
    selected_scans = get_scans_to_export(nessus_api)

    if not selected_scans:
        nessus_api.get_logger().error("No scans were selected. Exiting.")
        sys.exit(1)

    nessus_api.get_logger().info(f"Selected {len(selected_scans)} scan(s) for export.")
    
    # Export scans.
    csv_contents = {}  # key: scan_id, value: CSV content string
    if flags.threads > 1:
        nessus_api.get_logger().info(f"Exporting scans using {flags.threads} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=flags.threads) as executor:
            future_to_scan = {
                executor.submit(nessus_api.export_scan, scan_id): scan_id
                for scan_id in selected_scans
            }
            for future in concurrent.futures.as_completed(future_to_scan):
                scan_id = future_to_scan[future]
                scan_name, folder_name = selected_scans[scan_id]
                try:
                    content = future.result()
                    if content:
                        csv_contents[scan_id] = content
                        nessus_api.get_logger().info(f"Scan '{scan_name}' exported successfully.")
                    else:
                        nessus_api.get_logger().error(f"Failed to export scan '{scan_name}' (ID: {scan_id}).")
                except Exception as e:
                    nessus_api.get_logger().error(f"Error exporting scan '{scan_name}' (ID: {scan_id}): {e}")
    else:
        nessus_api.get_logger().info("Exporting scans sequentially...")
        for scan_id, (scan_name, folder_name) in selected_scans.items():
            nessus_api.get_logger().info(f"Exporting scan '{scan_name}' (ID: {scan_id}) from folder '{folder_name}'...")
            content = nessus_api.export_scan(scan_id)
            if content:
                csv_contents[scan_id] = content
                nessus_api.get_logger().info(f"Scan '{scan_name}' exported successfully.")
            else:
                nessus_api.get_logger().error(f"Failed to export scan '{scan_name}' (ID: {scan_id}).")

    if not csv_contents:
        nessus_api.get_logger().error("No CSV exports were obtained. Exiting.")
        sys.exit(1)

    # Merge CSV contents in the order the scans were selected.
    ordered_scan_ids = list(selected_scans.keys())
    csv_contents_list = [csv_contents[scan_id] for scan_id in ordered_scan_ids if scan_id in csv_contents]

    merge_csv_contents(csv_contents_list, file_name_to_export_to, nessus_api.get_logger(), mode=file_mode)
    nessus_api.get_logger().info("CSV merge process complete.")

    # If an Excel output filename is provided, convert the CSV to Excel.
    if flags.excel:
        excel_filename = flags.excel
        if not excel_filename.lower().endswith('.xlsx'):
            excel_filename += '.xlsx'
        nessus_convert(file_name_to_export_to, excel_filename, nessus_api.get_logger())
