# Aegis Android Extraction Tool

## Overview

Aegis Android Extraction Tool is a Python-based command-line utility designed to extract a variety of data from connected Android devices using the Android Debug Bridge (ADB). It provides a suite of modules for gathering comprehensive device information, user data, application-specific files, and more, saving them into structured, timestamped output directories for forensic analysis or backup purposes. The tool can attempt to leverage ADB root privileges for deeper data access if available and requested.

## Features

-   **Comprehensive Device Information**: Extracts detailed hardware, software, network, and system properties.
-   **Root-Aware Operations**: Ability to attempt `adb root` for deeper data access if the device allows and the user requests it. The script can also revert ADB to user mode upon completion if it was responsible for enabling root.
-   **Targeted Application Data Extraction**:
    -   If root access is available and enabled via `--attempt-root`, directly pulls application data folders from `/data/data/` and `/data/media/0/`.
    -   If root access is not available, attempts an `adb backup` for specified applications as a non-root fallback (success and data content vary by app). Backups are then unpacked using `abe.jar`.
    -   Supports a user-defined list of package names or a default list if none provided.
-   **Flexible File/Directory Pulling**: Allows pulling specific files or directories from the device (e.g., from `/sdcard/`). Users can specify paths or use a default list of common user data directories.
-   **Contacts Extraction**: Retrieves contacts (names, phone numbers, email addresses) from the content provider and saves them in CSV format.
-   **Call Logs Extraction**: Extracts call history (number, type, date, duration, cached name) from the content provider and saves it in CSV format.
-   **SMS Messages Extraction**: Pulls SMS/MMS messages (address, body, date, type) from the content provider and saves them in CSV format.
-   **Guided WhatsApp Key/Database Extraction**: A step-by-step guided process to extract the WhatsApp cryptographic key and message databases. This process involves user interaction for installing an older version of WhatsApp temporarily. (Requires Java and `abe.jar`).
-   **Basic Chrome Data Parsing**:
    -   Parses data from extracted Google Chrome (`com.android.chrome`) application files.
    -   Extracts History, Bookmarks, and Cookies into separate CSV files.
    -   Dumps the full Bookmarks JSON structure.
-   **Advanced Capture**:
    -   Screen recording of the device via `scrcpy`.
    -   Logcat dumps for detailed system logging.
-   **Structured Output**: All extracted data is saved in a main timestamped output directory (e.g., `aegis_output_YYYYMMDD_HHMMSS`), with subdirectories for each type of data.
-   **CLI Interface**: Controlled via a command-line interface with options to select specific modules, manage root attempts, override tool paths, and specify output locations.

## Prerequisites

Before using Aegis, ensure the following prerequisites are met:

1.  **Python**: Python 3.7 or newer is recommended.
2.  **ADB (Android Debug Bridge)**:
    -   Required for all operations.
    -   The script attempts to find `adb` (or `adb.exe`) in its directory, a `./bin` subdirectory, or the system PATH.
    -   Override with `--adb-path <path_to_adb>`.
    -   Download from: [SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools).
3.  **scrcpy (for Screen Recording)**:
    -   Optional, needed only for the screen recording feature (`--advanced-capture`).
    -   Finding logic and override (`--scrcpy-path`) are similar to ADB.
    -   Download from: [Genymobile/scrcpy Releases](https://github.com/Genymobile/scrcpy/releases). Ensure necessary DLLs (e.g., `SDL2.dll` on Windows) are with `scrcpy.exe`.
4.  **Java (for WhatsApp & App Backup Unpacking)**:
    -   Required for the Guided WhatsApp Extraction (`--whatsapp`) and for unpacking ADB backups of non-rooted targeted app data (`--app-data` without root).
    -   Java Runtime Environment (JRE) or JDK (version 8+ recommended) must be installed and accessible via `JAVA_HOME` or system PATH.
    -   Download from [Oracle Java Downloads](https://www.oracle.com/java/technologies/downloads/) or use OpenJDK.
5.  **`abe.jar` (Android Backup Extractor)**:
    -   Required for WhatsApp data extraction and non-root targeted app data backup unpacking.
    -   Place `abe.jar` in the script's directory or a `./bin` subdirectory.
    -   Download from: [android-backup-extractor Releases](https://github.com/nelenkov/android-backup-extractor/releases).

## Setup / Installation

1.  **Get the Script**: Clone the repository or download `aegis_android.py`.
2.  **Place Dependencies (Recommended for Auto-Detection)**:
    -   Create a `bin` folder in the same directory as `aegis_android.py`.
    -   Place `adb.exe` (and `AdbWinApi.dll`, `AdbWinUsbApi.dll` for Windows) in `bin/`.
    -   Place `scrcpy.exe` (and its DLLs) in `bin/`.
    -   Place `abe.jar` in `bin/` or the script's root directory.
    -   Alternatively, ensure `adb`, `scrcpy`, and `java` are correctly configured in your system's PATH.
3.  **Python Libraries**: Uses standard Python libraries. No special `pip install` steps are typically needed beyond a standard Python 3.7+ environment.

## Usage (CLI)

Run the script from your terminal. Ensure your Android device has **USB Debugging enabled**. For root-dependent features, the device must be rooted, and for ADB backup, "USB debugging (Security settings)" might need to be enabled in Developer Options.

**Basic Command Structure:**
`python aegis_android.py [module flags] [options]`

**Available Modules & Options:**

*   `--all`: Run all available extraction modules. Note: Does not automatically imply `--attempt-root`.
*   `--device-info`, `-di`: Extract comprehensive device hardware and software information.
*   `--pull-files`, `-pf`: Enable pulling files/directories. Use with `--pull-paths` or defaults will apply.
*   `--pull-paths [DEVICE_PATH ...]`: Specify space-separated full paths on the device to pull (e.g., `/sdcard/DCIM /sdcard/Pictures/Screenshots`). Effective only with `--pull-files`. If `--pull-files` is set but this is absent or empty, default directories are pulled.
*   `--contacts`, `-c`: Extract contacts.
*   `--call-logs`, `-cl`: Extract call logs.
*   `--sms`, `-s`: Extract SMS messages.
*   `--whatsapp`, `-wa`: Run the guided process for WhatsApp key and database extraction. This is an interactive process.
*   `--advanced-capture`, `-ac`: Perform advanced data capture (screen recording, logcat).
*   `--app-data [PACKAGE_NAME ...]`: Extract data for specific app(s). If no package names are provided, a default list (currently: "com.android.chrome", "org.telegram.messenger", "com.facebook.katana") will be attempted. Root access (`--attempt-root`) enables direct pulling from `/data/data/`; otherwise, an ADB backup is attempted.
*   `--parse-chrome`: Parse extracted Google Chrome data (History, Bookmarks, Cookies). Requires Chrome data to have been extracted first via `--app-data com.android.chrome` or as part of a default run with `--all`.
*   `--scrcpy-duration <SECONDS>`: Duration in seconds for screen recording if `--advanced-capture` is selected (default: 15).
*   `--attempt-root`: Attempt to restart ADB with root privileges. Required for certain data extractions like direct `/data/data` pulls.
*   `--output-dir <DIRECTORY_PATH>`, `-o <DIRECTORY_PATH>`: Base directory to save all extraction output. A timestamped folder will be created inside this. Default: Timestamped folder in the script's directory.
*   `--adb-path <FILE_PATH>`: Override the path to the ADB executable.
*   `--scrcpy-path <FILE_PATH>`: Override the path to the scrcpy executable.
*   `-h`, `--help`: Show the help message and exit.

**Usage Examples:**

1.  **Run all modules, attempting root, and save to a custom output location:**
    ```bash
    python aegis_android.py --all --attempt-root -o ./MyDeviceExtractions
    ```
    *(This will attempt to extract default apps and parse Chrome if it's among them).*
2.  **Extract device info, contacts, and pull specific app data for Chrome (attempting root), then parse Chrome data:**
    ```bash
    python aegis_android.py -di -c --attempt-root --app-data com.android.chrome --parse-chrome -o C:\CaseFiles\Device1
    ```
3.  **Pull default common user directories and extract targeted data for specific apps (non-root ADB backup attempt):**
    ```bash
    python aegis_android.py --pull-files --app-data com.example.app1 org.example.app2
    ```
4.  **Perform the guided WhatsApp key/database extraction:**
    ```bash
    python aegis_android.py --whatsapp
    ```
5.  **Perform advanced capture (screen recording for 60s and logcat):**
    ```bash
    python aegis_android.py --advanced-capture --scrcpy-duration 60
    ```

## Output Structure

Extracted data is organized within a main timestamped directory `aegis_output_YYYYMMDD_HHMMSS`:
-   `device_info/`: Contains `comprehensive_device_info.txt`.
-   `pulled_files/`: Subdirectories for each file/folder pulled via `--pull-files`.
-   `content_provider_data/`: CSV files for contacts, call logs, SMS.
-   `whatsapp_extraction/`: Data from the guided WhatsApp extraction (backup, key, DBs).
-   `rooted_app_data/<package_name>/`: Contains `data_data/` (from `/data/data/...`) and `data_media_0/` (from `/data/media/0/...`) if root extraction was successful for the app.
-   `app_backup_data/<package_name>/`: Contains the raw `.ab` backup and `_unpacked_tar_contents/` if non-root ADB backup and unpacking were successful for the app.
-   `parsed_app_data/<package_name>/`: Contains parsed data, e.g., for Chrome: `chrome_history.csv`, `chrome_bookmarks.csv`, `chrome_bookmarks_full.json`, `chrome_cookies.csv`.
-   `advanced_captures/`: Screen recordings (`.mp4`) and logcat dumps (`.txt`).
-   `aegis_extraction.log`: The main log file for the session.

## Targeted Application Data Extraction (`--app-data`)

-   This module allows extraction of data for specific applications.
-   **With Root (`--attempt-root` successful):** The tool will attempt to directly pull the application's sandboxed data from `/data/data/<package_name>` and its associated external data from `/data/media/0/<package_name>`. This provides the most comprehensive data. Output is saved to `rooted_app_data/<package_name>/`.
-   **Without Root:** The tool falls back to attempting an `adb backup` for the application.
    -   This method is **opportunistic**:
        -   Many modern applications explicitly disallow backup (`android:allowBackup="false"` in their manifest).
        -   Even if backup is allowed, it may not include all application data.
    -   If successful, the raw `.ab` backup file is saved, and the script attempts to unpack it using `abe.jar` into a TAR archive, which is then extracted. Output is saved to `app_backup_data/<package_name>/`.
-   If no package names are provided with `--app-data`, or if `--all` is used (and `--app-data` is not also used with specific packages), a default list of common applications (e.g., "com.android.chrome", "org.telegram.messenger", "com.facebook.katana") will be targeted.

## Chrome Data Parser (`--parse-chrome`)

-   This module processes data extracted from Google Chrome (`com.android.chrome`). It should be run after Chrome's data has been successfully extracted using the `--app-data com.android.chrome` flag (or as part of `--all`).
-   It searches for the Chrome profile data in the `rooted_app_data` or `app_backup_data` directories.
-   **Extracted Chrome Artifacts (saved in `parsed_app_data/com.android.chrome/`):**
    -   `chrome_history.csv`: Browsing history with timestamps, URLs, titles, visit counts.
    -   `chrome_bookmarks.csv`: Bookmarks with name, URL, and folder path.
    -   `chrome_bookmarks_full.json`: A full dump of the Bookmarks JSON structure for manual review.
    -   `chrome_cookies.csv`: Cookies with creation/access times, host, name, value, path, expiration, and security flags.
-   The parser handles potential errors gracefully, such as missing files or corrupted databases.

## License

This project is currently unlicensed. All rights reserved by the original author. (This is a placeholder; the repository owner should choose an appropriate open-source license if desired.)

## Future Goals

-   Packaging into a standalone executable (e.g., for Windows) using PyInstaller.
-   Adding more application-specific parsers.
-   Support for extracting data from specific file types within pulled app data (e.g., SQLite databases, Plists, XML).
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
