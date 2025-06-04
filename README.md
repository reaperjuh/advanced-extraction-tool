# Aegis Android Extraction Tool

## Overview

Aegis Android Extraction Tool is a Python-based command-line utility designed to extract a variety of data from connected Android devices using the Android Debug Bridge (ADB). It provides a suite of modules for gathering comprehensive device information, user data, application-specific files, and more, saving them into structured, timestamped output directories for forensic analysis or backup purposes.

## Features

-   **Comprehensive Device Information**: Extracts detailed hardware, software, network, and system properties.
-   **Flexible File/Directory Pulling**: Allows pulling specific files or directories from the device (e.g., from `/sdcard/`). Users can specify paths or use a default list of common user data directories.
-   **Contacts Extraction**: Retrieves contacts (names, phone numbers, email addresses) and saves them in CSV format.
-   **Call Logs Extraction**: Extracts call history (number, type, date, duration, cached name) and saves it in CSV format.
-   **SMS Messages Extraction**: Pulls SMS/MMS messages (address, body, date, type) and saves them in CSV format.
-   **Guided WhatsApp Key/Database Extraction**: A step-by-step guided process to extract the WhatsApp cryptographic key and message databases. This process involves user interaction for installing an older version of WhatsApp temporarily. (Requires Java and `abe.jar`).
-   **Advanced Capture**:
    -   Screen recording of the device via `scrcpy`.
    -   Logcat dumps for detailed system logging.
-   **Structured Output**: All extracted data is saved in a main timestamped output directory (e.g., `aegis_output_YYYYMMDD_HHMMSS`), with subdirectories for each type of data.
-   **CLI Interface**: Controlled via a command-line interface with options to select specific modules, override tool paths, and specify output locations.

## Prerequisites

Before using Aegis, ensure the following prerequisites are met:

1.  **Python**: Python 3.7 or newer is recommended. Standard Python installation is usually sufficient.
2.  **ADB (Android Debug Bridge)**:
    -   Required for all operations.
    -   The script will attempt to find `adb` (or `adb.exe` on Windows) in:
        1.  Its own directory.
        2.  A `./bin` subdirectory relative to the script.
        3.  The system's PATH environment variable.
    -   Users can override the ADB path using the `--adb-path` CLI argument.
    -   Download Platform Tools (which includes ADB) from the official Android developer website: [SDK Platform Tools release notes](https://developer.android.com/tools/releases/platform-tools).
3.  **scrcpy (for Screen Recording)**:
    -   Required only for the screen recording feature within "Advanced Capture" (`--advanced-capture` or `--all`).
    -   Finding logic is similar to ADB (script directory, `./bin`, system PATH).
    -   Users can override the scrcpy path using the `--scrcpy-path` CLI argument.
    -   Download scrcpy from its GitHub releases page: [Genymobile/scrcpy Releases](https://github.com/Genymobile/scrcpy/releases). Ensure you download the version appropriate for your OS and include any necessary DLLs (like `SDL2.dll`, `libusb-1.0.dll` on Windows) in the same location as `scrcpy.exe`.
4.  **Java (for WhatsApp Extraction)**:
    -   Required only for the Guided WhatsApp Key/Database Extraction feature (`--whatsapp` or `--all`) to unpack the ADB backup.
    -   Java Runtime Environment (JRE) or Java Development Kit (JDK) (version 8 or newer typically works) must be installed.
    -   The script attempts to find `java` (or `java.exe`) via the `JAVA_HOME` environment variable or the system's PATH.
    -   Download Java from [Oracle Java Downloads](https://www.oracle.com/java/technologies/downloads/) or consider alternatives like OpenJDK.
5.  **`abe.jar` (Android Backup Extractor - for WhatsApp Extraction)**:
    -   Required only for the Guided WhatsApp Key/Database Extraction feature (`--whatsapp` or `--all`). This tool unpacks the `whatsapp_backup.ab` file.
    -   `abe.jar` should be placed in the same directory as `aegis_android.py` or in a `./bin` subdirectory for auto-detection.
    -   Download `abe.jar` from a source like the [android-backup-extractor GitHub repository by Nikolay Elenkov](https://github.com/nelenkov/android-backup-extractor/releases) (look for `abe.jar` or compile from source).

## Setup / Installation

1.  **Get the Script**:
    -   Clone this repository or download the `aegis_android.py` script.
2.  **Place Dependencies for Auto-Detection (Recommended)**:
    -   Create a `bin` folder in the same directory as `aegis_android.py`.
    -   Place `adb.exe` (and its required DLLs: `AdbWinApi.dll`, `AdbWinUsbApi.dll` on Windows) into the `bin` folder.
    -   Place `scrcpy.exe` (and its required DLLs, e.g., `SDL2.dll`) into the `bin` folder.
    -   Place `abe.jar` into the `bin` folder (or the same directory as the script).
    -   Alternatively, ensure `adb`, `scrcpy`, and `java` are in your system's PATH.
3.  **Python Libraries**:
    -   The script primarily uses standard Python libraries (`os`, `subprocess`, `datetime`, `time`, `shutil`, `logging`, `csv`, `re`, `tarfile`, `pathlib`, `argparse`).
    -   No special `pip install -r requirements.txt` is needed if you have a standard Python 3.7+ installation.

## Usage (CLI)

Run the script from your terminal or command prompt. Ensure your Android device has **USB Debugging enabled** in Developer Options and is connected to your computer. For some features like ADB backup (used in WhatsApp extraction), you might need to enable additional "Security settings" related to USB debugging in Developer Options.

**Basic Command Structure:**
`python aegis_android.py [module flags] [options]`

**Available Modules & Options:**

*   `--all`: Run all available extraction modules.
*   `--device-info`, `-di`: Extract comprehensive device hardware and software information.
*   `--pull-files`, `-pf`: Enable pulling files/directories. Use with `--pull-paths` or defaults will apply.
*   `--pull-paths [DEVICE_PATH ...]`: Specify space-separated full paths on the device to pull (e.g., `/sdcard/DCIM /sdcard/Pictures/Screenshots`). Effective only with `--pull-files`. If `--pull-files` is set but this is absent or empty, default directories are pulled.
*   `--contacts`, `-c`: Extract contacts.
*   `--call-logs`, `-cl`: Extract call logs.
*   `--sms`, `-s`: Extract SMS messages.
*   `--whatsapp`, `-wa`: Run the guided process for WhatsApp key and database extraction. This is an interactive process.
*   `--advanced-capture`, `-ac`: Perform advanced data capture (screen recording, logcat).
*   `--scrcpy-duration <SECONDS>`: Duration in seconds for screen recording if `--advanced-capture` is selected (default: 15).
*   `--output-dir <DIRECTORY_PATH>`, `-o <DIRECTORY_PATH>`: Base directory to save all extraction output. A timestamped folder will be created inside this. Default: Timestamped folder in the script's directory.
*   `--adb-path <FILE_PATH>`: Override the path to the ADB executable.
*   `--scrcpy-path <FILE_PATH>`: Override the path to the scrcpy executable.
*   `-h`, `--help`: Show the help message and exit.

**Usage Examples:**

1.  **Run all extraction modules and save to a custom output location:**
    ```bash
    python aegis_android.py --all -o ./MyDeviceExtractions
    ```
2.  **Extract device info, contacts, and SMS messages:**
    ```bash
    python aegis_android.py -di -c -s --output-dir "C:\ForensicCases\Case001"
    ```
3.  **Pull specific directories from the device:**
    ```bash
    python aegis_android.py --pull-files --pull-paths /sdcard/DCIM/Camera /sdcard/Download /sdcard/WhatsApp/Media
    ```
4.  **Pull default common directories (DCIM, Downloads, Pictures, etc.):**
    ```bash
    python aegis_android.py --pull-files
    ```
5.  **Perform the guided WhatsApp key/database extraction:**
    ```bash
    python aegis_android.py --whatsapp
    ```
6.  **Perform advanced capture (screen recording for 60s and logcat):**
    ```bash
    python aegis_android.py --advanced-capture --scrcpy-duration 60
    ```

## Output

The tool creates a main output directory named `aegis_output_YYYYMMDD_HHMMSS` (where `YYYYMMDD_HHMMSS` is the timestamp of execution). Inside this directory, data is organized into subdirectories based on the extraction module:
-   `device_info/`: Contains `comprehensive_device_info.txt`.
-   `pulled_files/`: Contains subdirectories for each file/folder pulled from the device.
-   `content_provider_data/`: Contains CSV files for contacts, call logs, and SMS messages.
-   `whatsapp_extraction/`: Contains files from the WhatsApp extraction process (e.g., `whatsapp_backup.ab`, `key`, `msgstore.db`).
-   `advanced_captures/`: Contains screen recordings (`.mp4`) and logcat dumps (`.txt`).
-   `aegis_extraction.log`: The main log file for the entire session.

## License

This project is currently unlicensed. All rights reserved by the original author. (This is a placeholder; the repository owner should choose an appropriate open-source license if desired.)

## Future Goals

-   Packaging into a standalone executable (e.g., for Windows) using PyInstaller.
-   Adding more extraction modules (e.g., other messaging apps, browser history).
-   Support for rooted devices to access more data.
-   GUI interface.

## Developer Notes: Future Packaging (PyInstaller)

This section outlines considerations for packaging `aegis_android.py` into a standalone executable using PyInstaller.

### PyInstaller Command Examples

-   **One-file bundle (simpler distribution, potentially slower startup):**
    ```bash
    pyinstaller --noconsole --onefile --name AegisExtractor aegis_android.py
    ```
-   **One-directory bundle (faster startup, more files to distribute, easier to debug missing files):**
    ```bash
    pyinstaller --noconsole --onedir --name AegisExtractor aegis_android.py
    ```
    (The `--console` option can be kept during development for debugging.)

### Bundling Binaries and Assets

The script relies on external tools (`adb`, `scrcpy`, `abe.jar`) and potentially their associated DLLs. These must be bundled with the PyInstaller executable.

-   Use the `--add-binary` flag in PyInstaller. The syntax is `path/to/source/file:destination/folder/in/bundle`.
    ```bash
    pyinstaller --noconsole --onefile --name AegisExtractor \
        --add-binary "path_to_your_bin_folder/adb.exe:assets" \
        --add-binary "path_to_your_bin_folder/AdbWinApi.dll:assets" \
        --add-binary "path_to_your_bin_folder/AdbWinUsbApi.dll:assets" \
        --add-binary "path_to_your_bin_folder/scrcpy.exe:assets" \
        --add-binary "path_to_your_bin_folder/SDL2.dll:assets" \
        --add-binary "path_to_your_bin_folder/libusb-1.0.dll:assets" \
        # Add other scrcpy DLLs if needed (e.g., vcruntime140.dll, etc., though PyInstaller might pick these up)
        --add-binary "path_to_your_bin_folder/abe.jar:assets" \
        aegis_android.py
    ```
    Replace `path_to_your_bin_folder/` with the actual path to where these tools are stored during development.
    The destination folder within the bundle (e.g., `assets`) is arbitrary but must be consistent with how `_find_tool` is modified to look for them at runtime.

### Runtime Path Adjustment (`sys._MEIPASS`)

When bundled by PyInstaller, the script runs from a temporary directory. The path to this directory is available via `sys._MEIPASS`. The `_find_tool` (and `_find_java_executable` if Java were bundled) method needs to be aware of this to locate the bundled assets.

**Example Modification for `_find_tool`:**

```python
# At the top of aegis_android.py, ensure 'sys' is imported:
# import sys
# (Path from pathlib should already be imported)

# Inside the AegisExtractor class:
# def _find_tool(self, tool_name_full): # tool_name_full e.g. "adb.exe", "abe.jar"
#     logging.debug(f"Searching for tool: {tool_name_full}...")
#
#     # Check if running in a PyInstaller bundle
#     if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
#         bundle_dir = Path(sys._MEIPASS)
#
#         # Search in 'assets' subdirectory of bundle_dir first (if specified like that in --add-binary)
#         tool_path_bundle_assets = bundle_dir / 'assets' / tool_name_full
#         if tool_path_bundle_assets.exists():
#             # For executables, also check if it's executable
#             if not tool_name_full.endswith(".jar") and not os.access(tool_path_bundle_assets, os.X_OK):
#                 logging.warning(f"Found {tool_name_full} in PyInstaller bundle (assets) but it's not executable: {tool_path_bundle_assets}")
#             else:
#                 logging.info(f"Found {tool_name_full} in PyInstaller bundle (assets): {tool_path_bundle_assets}")
#                 return str(tool_path_bundle_assets)
#
#         # Optionally, search in root of bundle_dir if not in 'assets' (or other specified bundle subfolder)
#         tool_path_bundle_root = bundle_dir / tool_name_full
#         if tool_path_bundle_root.exists():
#             if not tool_name_full.endswith(".jar") and not os.access(tool_path_bundle_root, os.X_OK):
#                 logging.warning(f"Found {tool_name_full} in PyInstaller bundle (root) but it's not executable: {tool_path_bundle_root}")
#             else:
#                 logging.info(f"Found {tool_name_full} in PyInstaller bundle (root): {tool_path_bundle_root}")
#                 return str(tool_path_bundle_root)
#
#     # Existing search logic (script's directory, ./bin relative to script, system PATH)
#     # This part would remain as is, acting as a fallback if not bundled or if files are somehow
#     # not found in the bundle (which shouldn't happen if --add-binary is correct).
#     script_file_path = Path(__file__).resolve()
#     script_dir = script_file_path.parent
#
#     search_paths_config = [
#         {"path": script_dir, "label": "script directory"},
#         {"path": script_dir / 'bin', "label": "./bin subdirectory"},
#     ]
#     # ... (rest of the existing _find_tool logic) ...
```

**Important Notes for Packaging:**
-   The paths used in `--add-binary` (e.g., `assets/adb.exe`) must match the paths `_find_tool` checks within `sys._MEIPASS` (e.g., `bundle_dir / 'assets' / 'adb.exe'`).
-   DLLs like `vcruntime140.dll` and `vcruntime140_1.dll` might be needed by `scrcpy` or other C/C++ based tools. PyInstaller often bundles these automatically if they are direct dependencies of the Python interpreter or used by imported modules. However, for executables like `scrcpy.exe` that are bundled as data files, their own DLL dependencies need to be explicitly added with `--add-binary` and placed alongside them in the bundle.
-   The `_find_java_executable` method will continue to rely on Java being installed on the user's system and available via `JAVA_HOME` or PATH. Bundling a JRE is possible with PyInstaller but significantly increases package size and complexity.
-   Thorough testing of the bundled executable on a clean machine (without Python or any of these tools installed globally) is crucial.
```
