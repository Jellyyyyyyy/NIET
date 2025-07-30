# Convert Mode Configuration Guide

This guide explains how to customize `configs/convert_config.json` so that the Excel workbook produced by **convert mode** matches your desired layout. No Python knowledge is required – simply edit the JSON file following the instructions below.

## 1. Basic Settings

The top level options define the input/output files and optional keywords.

```json
{
  "mode": "convert",
  "verbose": false,
  "csv": "Ubuntu Machines_1452lr.csv",
  "excel": "nessus_export_output.xlsx",
  "software_exclusion_keywords": ["os", "startup", "start-up"],
  "excel_config_path": "...",
  "excel_config": { ... }
}
```

- **csv** – path to the Nessus CSV export you want to convert.
- **excel** – path for the generated Excel workbook.
- **software_exclusion_keywords** – words to ignore when listing installed software.
- **excel_config_path** – optional path to another JSON file containing the same `excel_config` section. Leave blank if not using.

## 2. `excel_config` Overview

Everything inside `excel_config` controls the workbook formatting and sheet behaviour. The supplied configuration already contains sensible defaults, but every part can be adjusted.

```json
"excel_config": {
  "remove_duplicates": true,
  "ip_regex": "...",
  "table": { ... },
  "status": { ... },
  "hosts": { ... },
  "sheet_options": { ... },
  "sheets": { ... }
}
```

### 2.1 Removing Duplicates
- **remove_duplicates** – Set to `true` to drop identical rows from the CSV before processing.

### 2.2 Host Detection
- **ip_regex** – Regular expression used to recognise IP addresses. Only change this if your host identifiers do not follow standard IP patterns.

### 2.3 Table Style
Controls how all tables look in Excel.

```json
"table": {
  "table_style": "TableStyleMedium9",
  "show_first_column": false,
  "show_last_column": false,
  "show_row_stripes": false,
  "show_column_stripes": false,
  "header_fill": "A5A5A5",
  "header_fill_type": "solid",
  "header_font_color": "000000",
  "cell_fill": "ffffff",
  "cell_fill_type": "solid",
  "cell_border": "thin",
  "cell_font_color": "000000"
}
```

Adjust colours or table styles as desired. Excel colour values are in hexadecimal (`RRGGBB`).

### 2.4 Status Column
Defines allowed values for the "Status" column and the colours used for conditional formatting.

```json
"status": {
  "status_map": {
    "-": "ffffff",
    "Open": "FFC7CE",
    "On-going": "FFEB9C",
    "Closed": "FFFFFF",
    "Declared": "82F073"
  },
  "status_fill_type": "solid"
}
```

Edit the keys in `status_map` to change the dropdown list values or update the associated colours.

### 2.5 Hosts Sheet
Controls the first sheet listing all unique hosts.

```json
"hosts": {
  "sheet_name": "Hosts",
  "table_name": "Hosts",
  "headers": ["Hostname", "IP", "OS"],
  "visible_columns": ["Hostname", "IP", "OS"],
  "ip_match": ["", 1, ""],
  "not_ip_match": [1, "", ""]
}
```

- **sheet_name** – name of the worksheet.
- **headers** – column titles.
- **ip_match / not_ip_match** – values inserted when the host identifier **is** or **is not** an IP address. A `1` means “copy the host text into this column”. Modify these arrays if you prefer different host information.

### 2.6 General Sheet Options
These options apply to all subsequent sheets produced from the CSV.

```json
"sheet_options": {
  "host_column_name": "Host",
  "insert_mapping_columns_after": "Risk",
  "mapping_columns": ["Hostname_original", "Hostname", "IP_original", "IP", "OS_original", "OS"],
  "ip_match": ["", "", 1, "", "", ""],
  "not_ip_match": [1, "", "", "", "", ""],
  "mapping_columns_formula": { ... },
  "additional_columns": {"Status": "Open", "Remarks": ""},
  "headers_to_remove": ["Host"]
}
```

- **host_column_name** – name of the column in the CSV that contains host identifiers.
- **insert_mapping_columns_after** – mapping columns listed in `mapping_columns` are inserted after this header.
- **mapping_columns** – columns added to look up host details from the Hosts sheet.
- **ip_match / not_ip_match** – default values placed in the mapping columns when the host text is an IP address or not.
- **mapping_columns_formula** – formulas automatically filled in these mapping columns so that host details update when edited.
- **additional_columns** – extra columns appended at the end of each sheet with initial values.
- **headers_to_remove** – headers from the CSV that should not appear in the new sheets.

### 2.7 Individual Sheet Rules
Under `sheets` you can define any number of worksheets. The defaults create five: vulnerabilities, compliance, open ports, users and installed software. Each sheet entry shares the same structure:

```json
"vulnerabilities": {
  "sheet_name": "Vulnerabilities",
  "case_insensitive": true,
  "filter": ["^None$", "^Low$", "^Medium$", "^High$", "^Critical$"],
  "column_filter_lookup": ["^Risk$"],
  "filter_exclude": [],
  "visible_columns": ["Risk", "Hostname", "IP", "OS", "Name", "Synopsis", "Description", "Solution", "See Also", "Plugin Output", "Status", "Remarks"],
  "auto_width_columns": [],
  "text_format_column": "Risk",
  "text_format": {"Low": "0000FF", "Medium": "A0522D", "High": "FF0000", "Critical": "8B0000"}
}
```

Key options:
- **sheet_name** – worksheet title.
- **case_insensitive** – whether text matching ignores case.
- **column_filter_lookup** – which CSV column(s) to inspect when determining if a row belongs to this sheet.
- **filter** – patterns that must match values in those columns. Rows matching at least one pattern are included.
- **filter_exclude** – patterns that remove rows even if they match `filter`.
- **visible_columns** – columns to show in Excel; others are hidden.
- **auto_width_columns** – list of columns whose width will be adjusted automatically.
- **text_format_column / text_format** – optional rules for colouring cell text based on its content.
- **extract_config** – (optional) instructions for pulling extra information out of "Plugin Output" values. Used in the Users and Installed Software sheets.

#### Extract Configuration Example
For the **users** sheet, the extract configuration tells the converter how to pull usernames from plugin output:

```json
"extract_config": {
  "case_insensitive": true,
  "lookup_columns": ["^Name$"],
  "extract_columns": ["^Plugin Output$"],
  "extract_column_name": "User",
  "linux": {
    "lookup_values": ["^Linux User List Enumeration$"],
    "extraction": {"regex": ["^User\\s*:\\s*(.+)$"], "exclude": []}
  },
  "windows": {
    "lookup_values": ["^Enumerate Users via WMI$"],
    "extraction": {"regex": ["^Name\\s*:\s*(.+)$"], "exclude": ["no\\.?\\s*of\\s*users"]}
  }
}
```

Adjust the regular expressions and lookup values if your CSV uses different plugin names or output formatting.

## 3. Customising for Your Needs
1. Copy `configs/convert_config.json` and edit the values described above.
2. Point the `csv` and `excel` fields to your files.
3. Adjust `sheets` rules to control which rows appear on each worksheet and which columns remain visible.
4. Modify colours or table options to suit your style.
5. Run convert mode with this configuration:
   ```bash
   python main.py -c -k path/to/your_config.json
   ```

## Summary
By updating the JSON fields—particularly under `excel_config`—you can tune every aspect of the output workbook: sheet names, filters, visible columns, colours and even how host information is looked up. Start with the provided configuration, change the parts that matter to you, and the converter will handle the rest.
