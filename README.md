# 📡 Nessus Import/Export Tool

[Nessus](https://www.tenable.com/products/nessus) is a widely-used vulnerability scanning tool. This project automates importing, exporting, converting, and combining Nessus vulnerability scans using Nessus' Web API. Developed primarily for Windows environments, this tool streamlines the management of Nessus scans through an easy-to-use command-line interface

## ✨ Features

- **[Import Scans](#import-mode)**: Import `.nessus` files to Nessus.
- **[Export Scans](#export-mode)**: Export Nessus scans to CSV or Excel.
- **[Convert CSV to Excel](#convert-mode)**: Format Nessus CSV outputs into structured Excel files.
- **[Combine Scans](#combine-mode)**: Merge multiple `.nessus` files into a single file.

## 📝 Requirements

- **Python 3.12+** (Developed and tested on Windows 10/11)
- Access to Nessus (tested primarily with Nessus Web Client API)

### Python Dependencies

Install dependencies via:

```bash
pip install -r requirements.txt
```

- requests==2.32.3
- urllib3==2.3.0
- openpyxl==3.1.5
- idna==3.10

## 🔎 Usage

```bash
python main.py [MODE] [OPTIONS]
```

## 🚜 Building

You can get the latest compiled release in the [Releases](https://github.com/Jellyyyyyyy/NIET/releases) section. If you want to, you can build it yourself as well (Pyinstaller is required for compiling):

```bash
pyinstaller --onefile main.py
```

## ⚡ Modes

### Import Mode

Imports `.nessus` files into your Nessus server, supporting interactive folder selection or creation and multi-threaded uploads.

**Example Configuration:**

```json
{
  "mode": "import",
  "nessus_url": "https://localhost:8834",
  "directory": ".\\",
  "upload_folder": "My Scans",
  "threads": 1
}
```

### Export Mode

Interactively export selected scans from Nessus to CSV, with optional Excel output and customizable threading for performance.

**Example Configuration:**

```json
{
  "mode": "export",
  "nessus_url": "https://localhost:8834",
  "csv": "nessus_export_output.csv",
  "excel": "nessus_export_output.xlsx",
  "threads": 1
}
```

### Convert Mode

Convert Nessus CSV reports into richly formatted Excel workbooks. Highly configurable through JSON files to define custom styles, extraction rules, conditional formatting, data validation, and sheet layouts.

**Excel Configurations include:**

- Customizable sheet formatting and coloring.
- Advanced extraction rules for vulnerabilities, compliance data, open ports, users, and installed software.
- Data validation and conditional formatting for easy analysis.

**Example Configuration:**

```json
{
  "mode": "convert",
  "csv": "Ubuntu Machines_1452lr.csv",
  "excel": "nessus_export_output.xlsx",
  "software_exclusion_keywords": ["os", "startup", "start-up"],
  "excel_config": {
    "table": {
      "header_fill": "A5A5A5",
      "header_font_color": "000000"
    },
    "status": {
      "status_map": {"Open": "FFC7CE", "On-going": "FFEB9C"}
    },
    "sheets": { ... }
}
```

### Combine Mode

Combine multiple `.nessus` scan files into a single consolidated file, handling duplicate host entries interactively or automatically.

**Example Configuration:**

```json
{
  "mode": "combine",
  "directory": "examples",
  "output": "merged_scan.nessus",
  "scan_name": "Merged Scan",
  "remove_duplicates": "ask"
}
```

## 🌐 Obtaining API Token

Obtain the required API token via browser developer tools:

1. Navigate to your Nessus Web UI.
2. Open developer tools (F12).
3. Inspect the network tab.
4. Retrieve the token from a request header that contains `X-API-Token`.

*Note: This method differs from the officially documented Nessus API token process.*

## ⚙️ Project Structure

- `main.py`: Main entry point.
- `NessusAPI.py`: Authentication and API interactions.
- `nessus_import.py`: Imports `.nessus` files.
- `nessus_export.py`: Exports scans to CSV and Excel.
- `nessus_convert.py`: Converts CSV outputs to Excel.
- `nessus_combine.py`: Combines `.nessus` files.
- `utils.py`: Helper functions used across modes.

## 🧑‍💻 Authors

- [Jellyyyyyyy](https://github.com/Jellyyyyyyy)
- [SimYanZhe](https://github.com/SimYanZhe)

## 📃 License

Distributed under the MIT License. See [LICENSE](https://github.com/Jellyyyyyyy/NIET/blob/main/LICENSE) for details.

## 🛟 Support

For issues or feature requests, please create a GitHub issue.

## 💎 GitHub

[Repository Link](https://github.com/Jellyyyyyyy/NIET)
