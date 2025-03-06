from datetime import datetime
import os
import re
import sys

from utils import gather_nessus_files, get_user_input_with_default

def trim_source_content(file_path):
    """
    Reads a source file and returns only the content from the first <ReportHost 
    to the last </ReportHost> (inclusive), discarding extraneous content.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # DOTALL mode: '.' matches newlines.
    match = re.search(r'(?s)(<ReportHost.*</ReportHost>)', content)
    if match:
        return match.group(1)
    else:
        return content

def get_nessus_report_hosts_from_content(content):
    """
    Extracts ReportHost blocks from the provided content.
    The regex looks for a <ReportHost ...> tag and lazily captures everything until the next
    <ReportHost ...> tag or the end of the string.
    """
    pattern = r'(<ReportHost[^>]*>.*?)(?=<ReportHost[^>]*>|$)'
    hosts = re.findall(pattern, content, flags=re.DOTALL)
    return hosts

def get_destination_hosts(file_path):
    """
    Extracts ReportHost blocks from the destination file.
    Assumes that each ReportHost block is wrapped with a closing </ReportHost> tag.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    pattern = r'(<ReportHost[^>]*>.*?</ReportHost>)'
    hosts = re.findall(pattern, content, flags=re.DOTALL)
    return hosts

def combine_hosts(dest_hosts_tuples, source_hosts_tuples, remove_duplicates_flag, logger=None):
    """
    Combines host blocks from the destination and source files.
    Each host block is paired with its 'name' attribute (if present) and its origin filepath.
    
    If remove_duplicates_flag is True, then for any host name that appears more than once
    the user is prompted (showing only the origin filepaths) to choose which file’s block to keep.
    Otherwise, all blocks are combined (duplicates left in).
    """
    # Combine both lists.
    combined = dest_hosts_tuples + source_hosts_tuples
    # Group by host name.
    host_dict = {}
    for block, host_name, origin in combined:
        host_dict.setdefault(host_name, []).append((block, origin))
    
    final_hosts = []
    for host_name, entries in host_dict.items():
        if len(entries) == 1:
            final_hosts.append(entries[0][0])
        else:
            if remove_duplicates_flag.lower() in ["ask", "auto"]:
                if remove_duplicates_flag == "ask":
                    print(f"Duplicate host found for name '{host_name}':")
                    for idx, (block, origin) in enumerate(entries, start=1):
                        print(f"{idx}. {origin}")
                valid_choice = False
                while not valid_choice:
                    try:
                        if remove_duplicates_flag == "auto":
                            choice = 1
                        else:
                            choice = get_user_input_with_default(f"Choose which file's ReportHost to keep for host '{host_name}' (1-{len(entries)}) [1]: ", default=1, logger=logger)
                        choice = int(choice)
                        if 1 <= choice <= len(entries):
                            final_hosts.append(entries[choice - 1][0])
                            valid_choice = True
                        else:
                            if logger:
                                logger.error("Invalid choice, please try again.")
                            else:
                                print("Invalid choice, please try again.")
                    except ValueError:
                        if logger:
                            logger.error("Please enter a valid number.")
                        else:
                            print("Please enter a valid number.")
            else:
                # If not removing duplicates, keep all.
                for block, origin in entries:
                    final_hosts.append(block)
    return final_hosts

def update_report_tag(content, new_report_name):
    """
    Updates the name attribute of the <Report> tag to new_report_name.
    If a name attribute already exists, it is replaced.
    If not, one is inserted after the <Report tag.
    """
    # Pattern to find a name attribute in the <Report> tag.
    pattern = r'(<Report\b[^>]*\bname\s*=\s*")([^"]*)(")'
    if re.search(pattern, content):
        content = re.sub(pattern, lambda m: f'{m.group(1)}{new_report_name}{m.group(3)}', content, count=1)
    else:
        # Insert the name attribute after <Report.
        content = re.sub(r'(<Report\b)', r'\1 name="{}"'.format(new_report_name), content, count=1)
    return content

def update_destination_file(destination_file, final_hosts, output_file, new_report_name=None, logger=None):
    """
    Removes all existing ReportHost blocks from the destination file, inserts the 
    final list of ReportHost blocks (resolved for duplicates) before the closing </Report> tag,
    and optionally updates the <Report> tag's name attribute.
    The updated content is then written to a new output file.
    """
    with open(destination_file, 'r', encoding='utf-8') as f:
        dest_content = f.read()
    
    # Remove all existing ReportHost blocks.
    dest_content_no_hosts = re.sub(r'(?s)<ReportHost[^>]*>.*?</ReportHost>', '', dest_content)
    
    # Combine final host blocks into one string.
    insert_content = "\n".join(final_hosts)
    
    # Insert the combined host blocks just before the closing </Report> tag.
    updated_content = re.sub(r'(</Report>)', lambda m: f"{insert_content}\n{m.group(1)}", dest_content_no_hosts)
    
    # If a new report name is provided, update the <Report> tag.
    if new_report_name:
        updated_content = update_report_tag(updated_content, new_report_name)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)

def nessus_combine(output, scan_name, directory=None, filepaths=None, logger=None, flags=None):    
    if flags is None:
        flags = {
            "remove_duplicates": "ask",
        }
        
    if not directory and not filepaths:
        logger.error("Need to provide either a directory or a list of filepaths.")
        sys.exit(1)
    
    if not scan_name:
        scan_name = get_user_input_with_default(f"Enter the new name for the merged scan (e.g. Merged Scan) [Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}]: ", validate=r'^[A-Za-z0-9_\-\s]+$', default=f"Merged Scan {datetime.now().strftime('%Y%m%d%H%M%S')}", logger=logger)
    
    # Process the destination file.
    if directory:
        logger.debug(f"Gathering Nessus files from {directory}")
        nessus_files = gather_nessus_files(directory)
        if filepaths:
            for filepath in filepaths:
                if os.path.isfile(filepath) and filepath.endswith('.nessus'):
                    nessus_files.append(filepath)
                else:
                    logger.error(f"File '{filepath}' is not a valid .nessus file.")
    else:
        nessus_files = filepaths
    
    if len(nessus_files) == 0:
        logger.error("No Nessus files found in the directory.")
        sys.exit(1)
        
    if len(nessus_files) == 1:
        logger.error("Need more than 1 Nessus file in the directory to combine.")
        sys.exit(1)
    
    destination_file = nessus_files[0]
    
    dest_hosts_list = get_destination_hosts(destination_file)
    dest_hosts_tuples = []
    for host in dest_hosts_list:
        m = re.search(r'name\s*=\s*"([^"]+)"', host)
        host_name = m.group(1) if m else None
        dest_hosts_tuples.append((host, host_name, destination_file))
    
    # Process each source file.
    source_hosts_tuples = []
    for src_file in nessus_files[1:]:
        trimmed_content = trim_source_content(src_file)
        src_hosts = get_nessus_report_hosts_from_content(trimmed_content)
        for host in src_hosts:
            m = re.search(r'name\s*=\s*"([^"]+)"', host)
            host_name = m.group(1) if m else None
            source_hosts_tuples.append((host, host_name, src_file))
    
    # Combine hosts from destination and all source files.
    logger.debug(f"Combining Nessus files...")
    final_hosts = combine_hosts(dest_hosts_tuples, source_hosts_tuples, flags.remove_duplicates, logger=logger)
    
    # Update the destination file and write the result to the output file.
    update_destination_file(destination_file, final_hosts, output, new_report_name=scan_name, logger=logger)
    logger.info(f"Combined Nessus files into {output}")


