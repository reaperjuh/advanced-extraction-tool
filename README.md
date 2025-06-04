# advanced-extraction-tool
An advanced offline data extraction tool with forensic-level features, modern GUI, and encryption support.

## Enhanced Log Analyzer (`log_analyzer.py`)

**Overview:**
`log_analyzer.py` is a powerful Python script for parsing, filtering, and displaying Android's `logcat -v threadtime` formatted logs. It allows for real-time analysis from `adb logcat` or processing of saved log files, with options for console highlighting and structured output to CSV or JSON formats. This tool helps in debugging and analyzing log data by focusing on relevant entries.

**Usage:**

*   **Live analysis with `adb logcat`:**
    ```bash
    adb logcat -v threadtime [adb_options] | python log_analyzer.py [script_options]
    ```
    *(Note: On Windows, you might need `python.exe` or `py` instead of `python`)*

*   **Analysis from a log file:**
    ```bash
    python log_analyzer.py --input-file <path_to_log_file> [script_options]
    ```

**Command-Line Arguments:**

*   `--input-file FILE`: Path to a log file to read from. If not provided, reads from stdin.
*   `--min-priority {V,D,I,W,E,F}`: Minimum log priority to display (Verbose, Debug, Info, Warning, Error, Fatal). Case-insensitive.
*   `--tag TAG`: Log tags to include. Can be specified multiple times (e.g., `--tag MyApp --tag YourService`). Only messages with these tags are shown.
*   `--pid PID`: Process IDs to include. Can be specified multiple times (e.g., `--pid 1234 --pid 5678`).
*   `--keyword KEYWORD`: Keywords to search for in the log message. Case-insensitive. Can be specified multiple times (e.g., `--keyword error --keyword critical`). Only messages containing at least one keyword are shown.
*   `--highlight-keyword KEYWORD`: Keywords to highlight in the console output (makes the line bold). Case-insensitive. Can be specified multiple times. This applies on top of other filters.
*   `--output-csv CSV_FILE`: Path to save filtered logs as a CSV file. Includes a header row.
*   `--output-json JSON_FILE`: Path to save filtered logs (as parsed objects) in a JSON file.

**Examples:**

1.  **Show only errors and warnings from live `adb logcat`:**
    ```bash
    adb logcat -v threadtime | python log_analyzer.py --min-priority W
    ```

2.  **Show logs from tag "MyApp" and PID 1234, highlighting messages containing "database":**
    ```bash
    adb logcat -v threadtime | python log_analyzer.py --tag MyApp --pid 1234 --highlight-keyword database
    ```

3.  **Read from `my_logs.txt`, filter for messages containing "NetworkFailure" or "Exception", and save to CSV and JSON:**
    ```bash
    python log_analyzer.py --input-file my_logs.txt --keyword NetworkFailure --keyword Exception --output-csv filtered_logs.csv --output-json filtered_logs.json
    ```

4.  **Show all logs from `adb logcat` but highlight messages from tag "AudioFlinger" in bold (useful for spotting specific tag activity):**
    ```bash
    adb logcat -v threadtime | python log_analyzer.py --highlight-keyword AudioFlinger --tag AudioFlinger
    ```
    *(Note: Added `--tag AudioFlinger` to also filter by it, if only highlighting for this tag is desired among all logs, one might adjust filters accordingly or rely on visual scanning of bolded lines.)*

## Automated Artifact Extractor (`artifact_extractor.py`)

**Overview:**
`artifact_extractor.py` is a command-line tool designed to automate the extraction of common forensic artifacts from a connected Android device. It uses the Android Debug Bridge (ADB) to pull files, directories, and execute commands based on a predefined database of known artifacts.

**Prerequisites:**

*   **Android Debug Bridge (`adb.exe`):** The script requires `adb.exe` to be accessible. It will look for `adb.exe` in the same directory as the script, in the repository root, and then in the system's PATH.
*   **Root Access:** Many valuable forensic artifacts are stored in locations on the Android device that require root access. While the script will attempt to extract all specified artifacts, those requiring root may fail if the connected device is not rooted or ADB does not have root privileges.
*   **USB Debugging:** Ensure USB Debugging is enabled on the target Android device.

**Usage:**

The basic command structure is:
```bash
python artifact_extractor.py --output <output_directory> [options]
```
*(Note: On Windows, you might need `python.exe` or `py` instead of `python`)*

**Command-Line Arguments:**

*   `--output DIRECTORY`: **(Required)** Specifies the base directory where all extracted artifacts will be saved. A subdirectory for the target device will be created here.
*   `--artifacts ARTIFACT_KEYS`: A comma-separated list of specific artifact keys to extract (e.g., `sms_mms_db,contacts_db,build_prop`). Use `--list-artifacts` to see available keys.
*   `--all`: If specified, the script will attempt to extract all artifacts defined in its internal database.
*   `--list-artifacts`: Lists all available artifact keys and their display names from the internal database, then exits.
*   `--device SERIAL`: Specify the target device serial number. This is required if multiple Android devices/emulators are connected. If only one device is connected, the script will auto-detect it.
*   `-v, --verbose`: Enables verbose output, which includes printing the ADB commands being executed and more detailed information about the extraction process.

**Listing Available Artifacts:**

To see a list of all artifacts the script knows how to extract, run:
```bash
python artifact_extractor.py --list-artifacts
```
This will output a list of keys (e.g., `contacts_db`, `build_prop`) and their user-friendly display names (e.g., "Contacts Database", "Build Properties").

**Examples:**

1.  **Extract specific artifacts to `./extracted_data`:**
    ```bash
    python artifact_extractor.py --output ./extracted_data --artifacts "build_prop,device_properties,installed_packages"
    ```

2.  **Extract all defined artifacts from device `emulator-5554` with verbose output:**
    ```bash
    python artifact_extractor.py --output ./all_device_artifacts --all --device emulator-5554 --verbose
    ```

3.  **List all available artifacts:**
    ```bash
    python artifact_extractor.py --list-artifacts
    ```

**Output Structure:**

Extracted artifacts are organized within the specified output directory as follows:
```
<output_directory>/
└── <device_serial_number>/  (Directory named after the device's serial)
    ├── User Data/
    │   ├── contacts2.db
    │   └── mmssms.db
    ├── Device Information/
    │   ├── build.prop
    │   └── device_properties.txt
    ├── System Configuration/
    │   └── WifiConfigStore.xml
    └── Media_SD Card/
        └── DCIM/
            └── (pulled DCIM contents)
    └── ... (other categories)
```
Each artifact is saved into a subdirectory corresponding to its category (e.g., "User Data", "Device Information", "Media/SD Card"). This helps in keeping the extracted data organized.
